"""CLI の契約（1-1）。

    gate scan   --root <dir> --phase <off|notice|error> [--changed-files f] --out findings.json
    gate render --input findings.json --format <actions|sarif|text>

`scan` は常に exit 0 で JSON を書く。落とす判断は `render` 側。
こう切っておくと、PR ゲートと定期スキャンが同じ JSON を別の形で消費できる。

可視性は既定で public 扱い（＝出力をマスクする）。指定し忘れたときに詳細が
public な annotation に出るより、マスクされて読めない方が安全側に倒れる。
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys
from pathlib import Path

from . import __version__
from . import phase as phase_mod
from . import render as render_mod
from . import scope as scope_mod
from .model import Report
from .scan import scan


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="gate", description="GitHub Actions セキュリティゲート — 判定エンジン"
    )
    ap.add_argument("--version", action="version", version=f"gha-gate {__version__}")
    sub = ap.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="判定を走らせて findings JSON を書く（常に exit 0）")
    s.add_argument("--root", default=".", help="解析対象のディレクトリ（既定: .）")
    s.add_argument("--phase", default=phase_mod.ERROR, choices=list(phase_mod.ALL),
                   help="off=判定しない / notice=判定するが落とさない / error=検出で落とす")
    s.add_argument("--changed-files", metavar="FILE",
                   help=f"PR の変更ファイル一覧（1 行 1 パス）。対象: {scope_mod.TARGET_DESCRIPTION}")
    s.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""),
                   help="owner/name。出力に載せるだけで判定には使わない")
    s.add_argument("--visibility", choices=list(render_mod.VISIBILITIES),
                   help="対象リポジトリの可視性（既定: public 扱いでマスク）")
    s.add_argument("--no-ignores", action="store_true",
                   help="repo 側の ignore を無効化する（定期スキャン用。PR ゲートでは付けない）")
    s.add_argument("--no-config", action="store_true",
                   help="repo 側の .github/zizmor.yml を無視する（定期スキャン用）")
    s.add_argument("--no-ignore-lint", action="store_true",
                   help="理由・期限の無い ignore を検出しない（運用設計 §3.3 の lint を切る）")
    s.add_argument("--no-include-indirect", action="store_true",
                   help="untrusted-checkout の step 出力経由を検出しない（recall 95%% → 43%%）")
    s.add_argument("--extra-rule", action="append", default=[], metavar="AUDIT",
                   help="単独ルールに audit を追加する（繰り返し可）")
    s.add_argument("--zizmor-json", metavar="FILE",
                   help="zizmor を起動せず、既存の json-v1 出力を使う")
    s.add_argument("--today", metavar="YYYY-MM-DD", help="ignore の期限判定に使う日付（試験用）")
    s.add_argument("--out", metavar="FILE", help="findings JSON の出力先（既定: 標準出力）")

    r = sub.add_parser("render", help="findings JSON を人/機械向けに整形し、落とすかを決める")
    r.add_argument("--input", metavar="FILE", help="findings JSON（既定: 標準入力）")
    r.add_argument("--format", default="text", choices=sorted(render_mod.RENDERERS),
                   help="actions=ワークフローコマンド / sarif=Code Scanning / text=人向け")
    r.add_argument("--visibility", choices=list(render_mod.VISIBILITIES),
                   help="scan 時の指定を上書きする")
    r.add_argument("--phase", choices=list(phase_mod.ALL), help="scan 時の指定を上書きする")
    r.add_argument("--on-engine-error", default="fail", choices=("fail", "pass"),
                   help="エンジンが壊れたときに落とすか（既定: 落とす）")
    r.add_argument("--out", metavar="FILE", help="出力先（既定: 標準出力）")
    r.add_argument("--no-step-summary", action="store_true",
                   help="$GITHUB_STEP_SUMMARY への追記をしない")
    return ap


def cmd_scan(args: argparse.Namespace) -> int:
    zizmor_findings = None
    if args.zizmor_json:
        zizmor_findings = json.loads(Path(args.zizmor_json).read_text(encoding="utf-8"))

    changed = None
    if args.changed_files:
        changed = scope_mod.read_changed_files(args.changed_files)

    today = _dt.date.fromisoformat(args.today) if args.today else None
    visibility = args.visibility or render_mod.PUBLIC

    report = scan(
        args.root,
        phase=args.phase,
        changed_files=changed,
        repo=args.repo,
        visibility=visibility,
        no_ignores=args.no_ignores,
        no_config=args.no_config,
        ignore_lint=not args.no_ignore_lint,
        include_indirect=not args.no_include_indirect,
        extra_rules=tuple(args.extra_rule),
        zizmor_findings=zizmor_findings,
        today=today,
    )
    if args.visibility is None:
        report.status.degraded.append(
            "--visibility の指定が無いため public 扱いで出力をマスクした"
        )

    payload = json.dumps(report.to_dict(), ensure_ascii=False, indent=1)
    if args.out:
        Path(args.out).write_text(payload + "\n", encoding="utf-8")
    else:
        sys.stdout.write(payload + "\n")
    return phase_mod.EXIT_PASS       # scan は落とさない（1-1）


def cmd_render(args: argparse.Namespace) -> int:
    raw = Path(args.input).read_text(encoding="utf-8") if args.input else sys.stdin.read()
    report = Report.from_dict(json.loads(raw))
    if args.phase:
        report.phase = args.phase
    visibility = args.visibility or report.target.get("visibility") or render_mod.PUBLIC

    text = render_mod.RENDERERS[args.format](report, visibility)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    else:
        sys.stdout.write(text + "\n")

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary and args.format != "sarif" and not args.no_step_summary:
        try:
            with open(summary, "a", encoding="utf-8") as fh:
                fh.write("\n```\n" + render_mod.render_text(report, visibility) + "```\n")
        except OSError:
            pass
    return render_mod.decide_exit(report, on_engine_error=args.on_engine_error)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return {"scan": cmd_scan, "render": cmd_render}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())

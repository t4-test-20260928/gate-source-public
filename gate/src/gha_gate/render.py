"""出力（1-1 の render 側 / 1-5 の可視性切り替え / 1-6 の exit code）。

`scan` は常に exit 0 で JSON を書く。落とす判断はここで行う。判定結果の生成と
「落とすかどうか」を分けておくと、PR ゲートと定期スキャンが同じ JSON を別の
形で消費できる。

可視性による出力切り替え（差分 #6）:
  public リポジトリでは workflow の run とその annotation が未認証の誰にでも見える
  （実測）。脆弱な箇所の説明をそこに出すと、それ自体が攻撃の手引きになる。
  public では rule 名と指紋だけを出し、詳細は出さない。
"""

from __future__ import annotations

import json
from typing import Any

from . import ENGINE_NAME, __version__
from . import phase as phase_mod
from .model import Finding, Report

PUBLIC = "public"
PRIVATE = "private"
INTERNAL = "internal"
VISIBILITIES = (PUBLIC, PRIVATE, INTERNAL)

_SARIF_LEVEL = {"High": "error", "Medium": "warning", "Low": "note"}

_MASKED_NOTE = "詳細は非公開。指紋で中央の記録と突き合わせること"


def is_masked(visibility: str) -> bool:
    return visibility == PUBLIC


def message(f: Finding, visibility: str) -> str:
    if is_masked(visibility):
        return f"{f.rule} / fingerprint={f.short_fingerprint} — {_MASKED_NOTE}"
    parts = [f.desc or f.rule]
    if f.detail:
        parts.append(f.detail)
    if f.partners:
        parts.append("相方: " + ", ".join(f.partners))
    if f.fix:
        parts.append("修正案: " + f.fix)
    return " / ".join(p for p in parts if p)


def render_text(report: Report, visibility: str = PRIVATE) -> str:
    out: list[str] = []
    st = report.status
    head = {
        "off": "gha-gate: OFF — phase=off のため判定していない",
        "no-input": "gha-gate: SKIP — 監査対象の workflow / action 定義が無い",
        "skipped": f"gha-gate: SKIP — {st.message}",
    }.get(st.reason)

    if st.is_error:
        out.append("gha-gate: ENGINE ERROR — 判定が成立していない（検出 0 件ではない）")
        out.append(st.message)
        return "\n".join(out)
    if head:
        out.append(head)
    elif report.findings:
        verdict = "FAIL" if phase_mod.BLOCKS_ON_FINDINGS[report.phase] else "DETECTED"
        out.append(f"gha-gate: {verdict} — {len(report.findings)} 件 (phase={report.phase})")
    else:
        out.append(f"gha-gate: PASS — 検出 0 件 (phase={report.phase})")

    if st.degraded:
        out.append("")
        out.append("判定の到達範囲に制限あり:")
        out += [f"  - {d}" for d in st.degraded]

    if report.scope:
        scope = report.scope
        out.append("")
        out.append(
            f"スコープ: {scope.get('mode')} / 対象 {len(scope.get('files') or [])} ファイル"
            + (f" — {scope.get('reason')}" if scope.get("reason") else "")
        )

    if report.findings:
        out.append("")
        by_rule: dict[str, list[Finding]] = {}
        for f in report.findings:
            by_rule.setdefault(f.rule, []).append(f)
        for rule, fs in sorted(by_rule.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            kinds = sorted({f.kind for f in fs})
            out.append(f"## {rule}  ({len(fs)} 件 / {'+'.join(kinds)})")
            if not is_masked(visibility) and fs[0].url:
                out.append(f"   {fs[0].url}")
            for f in fs:
                loc = f"{f.path}:{f.line}" if f.line else f.path
                if f.job and not is_masked(visibility):
                    loc += f"  (job: {f.job})"
                out.append(f"   - {loc}  [{f.short_fingerprint}]")
                body = message(f, visibility)
                if body:
                    out.append(f"     └ {body}")
            out.append("")

    if report.suppressed:
        out.append(f"ignore で抑止: {len(report.suppressed)} 件")
        if not is_masked(visibility):
            for f in report.suppressed:
                s = f.suppression or {}
                out.append(
                    f"   - {f.rule} {f.path}:{f.line}  reason={s.get('reason','')} "
                    f"until={s.get('until','')} ticket={s.get('ticket','')}"
                )
    return "\n".join(out).rstrip() + "\n"


def render_actions(report: Report, visibility: str = PRIVATE) -> str:
    """GitHub Actions のワークフローコマンド + 人が読む本文。"""
    lines: list[str] = []
    level = phase_mod.ANNOTATION_LEVEL.get(report.phase)

    if report.status.is_error:
        lines.append(
            "::error title=gha-gate engine error::"
            + _one_line(report.status.message or "判定が成立していない")
        )
    elif level:
        for f in report.findings:
            loc = f"file={f.path}"
            if f.line:
                loc += f",line={f.line}"
            title = f"gha-gate {f.rule}"
            lines.append(f"::{level} {loc},title={title}::{_one_line(message(f, visibility))}")

    lines.append(render_text(report, visibility))
    return "\n".join(lines)


def render_sarif(report: Report, visibility: str = PRIVATE) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for f in report.findings:
        if f.rule not in rules:
            rule: dict[str, Any] = {"id": f.rule, "name": f.rule}
            if not is_masked(visibility):
                rule["shortDescription"] = {"text": f.desc[:120] or f.rule}
                if f.url:
                    rule["helpUri"] = f.url
            rules[f.rule] = rule
        results.append({
            "ruleId": f.rule,
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": message(f, visibility)},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.path},
                    "region": {"startLine": max(f.line, 1)},
                }
            }],
            "partialFingerprints": {"ghaGate/v1": f.fingerprint},
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": ENGINE_NAME,
                "version": __version__,
                "informationUri": "https://docs.zizmor.sh/",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, ensure_ascii=False, indent=1)


def decide_exit(report: Report, on_engine_error: str = "fail") -> int:
    """落とすかどうかを決める（1-6 / 1-7）。

    「検出があるから落とす」は phase に従う。「エンジンが壊れたから落とす」は
    phase に関係なく落とす。notice が握り潰すのは検出だけで、ツールの失敗ではない。
    """
    if report.status.is_error:
        return phase_mod.EXIT_PASS if on_engine_error == "pass" else phase_mod.EXIT_ENGINE_ERROR
    if report.findings and phase_mod.BLOCKS_ON_FINDINGS.get(report.phase, False):
        return phase_mod.EXIT_FINDINGS
    return phase_mod.EXIT_PASS


def _one_line(text: str) -> str:
    return " ".join((text or "").split())


RENDERERS = {"text": render_text, "actions": render_actions, "sarif": render_sarif}

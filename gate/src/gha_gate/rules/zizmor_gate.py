"""gate A — zizmor の json-v1 出力に対する判定。

移植元は、設計案に載っていた版ではなく**全数スキャンを実際に回した版**。両者には差があり、
後者にだけ `key.Local.verbatim_path` を拾う修正が入っている。拾い損ねると全検出が同じ
"?" に畳まれ、ファイル単位の同居ルールが別ファイル同士で誤成立する（実測で誤検出が大きく
膨らんだ）。

判定は 2 種類。

1. 単独ルール    … その audit が出たら止める。ただし severity=High のものだけ
2. 同居ルール    … 単独では止めず、同じ workflow ファイル内に相方がいるときだけ止める

なぜ audit 名で列挙し persona / confidence で絞らないか:
  - insecure-commands は persona=Auditor なので persona で絞ると消える
  - github-env       は confidence=Low   なので confidence で絞ると消える
  どちらも severity は High。「重大だが zizmor の既定フィルタで落ちる」ものが
  ゲートの本命なので、フィルタではなく列挙で指定する。

なぜ同居の単位が「ファイル」か:
  dangerous-triggers は route が `on`、つまり workflow ファイル全体に付く。
  そのファイル内の全 job がその trigger を継承するので、job 単位に絞る意味がない。
"""

from __future__ import annotations

import collections
from typing import Any, Iterable

from ..model import GATE_A, Finding

#: 単独で止める audit
GATE = frozenset({
    "impostor-commit",           # SHA 固定が参照先の ref から到達できない
    "insecure-commands",         # ACTIONS_ALLOW_UNSECURE_COMMANDS
    "github-env",                # $GITHUB_ENV / $GITHUB_PATH への注入
    "known-vulnerable-actions",  # 既知脆弱性のある action バージョン
})

#: 同居しているときだけ止める audit
#  dangerous-triggers(pull_request_target / workflow_run) は広く使われており、
#  単独で止めると多くのリポジトリが止まって形骸化する（実測値は運用側の記録を参照）。「危険な trigger」かつ「そこから踏める
#  中身」が同じファイルに揃ったときだけ止める。
PAIR_RULES: dict[str, dict[str, Any]] = {
    "dangerous-triggers": {
        "partners": {
            "template-injection",   # 相方として数えるのは High だけ（PARTNER_HIGH_ONLY）
            "github-env",
            "cache-poisoning",
            "insecure-commands",
        },
        "why": "危険な trigger と、そこから踏める中身が同じ workflow に揃っている",
    },
}
PARTNER_HIGH_ONLY = frozenset({"template-injection"})

#: online 監査でしか判定できない audit。参照先が引けずに --offline に落ちた場合、
#  この 2 つは「見られていない」ので、その旨を status.degraded に残す（#5 / fail-open）。
ONLINE_ONLY = frozenset({"impostor-commit", "known-vulnerable-actions"})


def primary(f: dict) -> dict:
    return next(
        (l for l in f["locations"] if l["symbolic"]["kind"] == "Primary"), f["locations"][0]
    )


def where(f: dict) -> tuple[str, int, str]:
    """検出の (path, line, job) を取り出す。"""
    l = primary(f)
    k = l["symbolic"]["key"]
    # Remote 監査は key.Remote.path、ローカル監査(--offline)は key.Local.verbatim_path。
    kk = k.get("Remote") or k.get("Local") or {}
    path = kk.get("path") or kk.get("verbatim_path") or "?"
    if "/.github/" in path:            # clone 先のプレフィクスを落として repo 相対にする
        path = path[path.index("/.github/") + 1:]
    row = l["concrete"]["location"]["start_point"]["row"] + 1
    route = [
        (s.get("Key") if "Key" in s else str(s.get("Index")))
        for s in l["symbolic"].get("route", {}).get("route", [])
    ]
    job = route[1] if len(route) > 1 and route[0] == "jobs" else ""
    return path, row, job


def evidence(f: dict) -> tuple[str, str, str]:
    """該当行そのもの / GHSA 等の注記 / zizmor が出す修正案。

    修正案を「どのファイルの何行目」だけで渡しても直せないので、ここまで持つ。
    """
    l = primary(f)
    feat = (l.get("concrete") or {}).get("feature") or ""
    anno = (l.get("symbolic") or {}).get("annotation") or ""
    fixes = [x.get("title", "") for x in (f.get("fixes") or []) if x.get("title")]
    return feat.strip()[:160], anno, "; ".join(fixes)[:200]


def evaluate(findings: Iterable[dict], extra_rules: Iterable[str] = ()) -> list[Finding]:
    """zizmor の json-v1 出力（findings のリスト）から gate A の検出を作る。"""
    gate = set(GATE) | {r for r in extra_rules if r}

    by_file: dict[str, dict[str, list]] = collections.defaultdict(
        lambda: collections.defaultdict(list)
    )
    for f in findings:
        path, row, job = where(f)
        by_file[path][f["ident"]].append((f, row, job))

    out: list[Finding] = []
    for path, idents in by_file.items():
        # 1. 単独ルール
        for ident in idents:
            if ident not in gate:
                continue
            for f, row, job in idents[ident]:
                if f["determinations"]["severity"] != "High":
                    continue
                feat, anno, fix = evidence(f)
                out.append(
                    Finding(
                        rule=ident, path=path, line=row, job=job,
                        severity=f["determinations"]["severity"],
                        gate=GATE_A, kind="single", source=feat,
                        desc=f.get("desc", ""), url=f.get("url", ""),
                        annotation=anno, fix=fix,
                    )
                )

        # 2. 同居ルール
        for trigger, rule in PAIR_RULES.items():
            if trigger not in idents:
                continue
            partners: list[str] = []
            for p in rule["partners"]:
                for f, row, job in idents.get(p, []):
                    if p in PARTNER_HIGH_ONLY and f["determinations"]["severity"] != "High":
                        continue
                    partners.append(f"{p}@{job or '-'}:{row}")
            if not partners:
                continue          # 相方がいない = 止めない
            shown = sorted(set(partners))[:6]
            for f, row, job in idents[trigger]:
                feat, anno, fix = evidence(f)
                out.append(
                    Finding(
                        rule=trigger, path=path, line=row, job=job,
                        severity=f["determinations"]["severity"],
                        gate=GATE_A, kind="paired", source=feat,
                        desc=f.get("desc", ""), url=f.get("url", ""),
                        partners=shown, annotation=anno, fix=fix,
                        detail=rule["why"] + " → " + ", ".join(shown),
                    )
                )
    return out

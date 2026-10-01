"""gate B — 特権 trigger での PR head checkout（自前ルール）。

CodeQL の actions/untrusted-checkout 相当。zizmor には該当する audit が無いので
自前で持つ。移植元は全数スキャンを回した版の `gate_b()`（設計案の
`untrusted-checkout-gate.py` に `--include-indirect` を付けた状態と同じ判定）。

精度（CodeQL の critical/high を正解データとして測定）:

    ref: が PR 由来の式を直接参照        recall 43%
    + steps.*.outputs 経由も含める       recall 95%

indirect を含めないと半分以上を取り逃すので、既定で含める。
サンプル実装からの差は行番号を持つことだけで、判定そのものは変えていない
（指紋の材料に「該当行」が要るため。移植元は line=0 固定だった）。
"""

from __future__ import annotations

import re

from ..model import GATE_B, Finding
from ..yamlline import line_of, safe_load, source_line

RULE = "untrusted-checkout"

#: 特権 trigger。ここに当たらない workflow は見ない
PRIV = frozenset({"pull_request_target", "workflow_run", "issue_comment"})

#: checkout の ref に現れたら「信頼できない」とみなす式
UNTRUSTED = re.compile(
    r"""github\.event\.pull_request\.head|
        github\.head_ref|
        github\.event\.workflow_run\.head|
        github\.event\.issue|
        github\.event\.comment|
        github\.event\.client_payload""",
    re.X,
)

#: step 出力経由（中身を追えないので「疑わしい」扱い）
INDIRECT = re.compile(r"steps\.[A-Za-z0-9_\-]+\.outputs\.")

#: run: の中で PR を checkout している形
RUN_CHECKOUT = re.compile(r"gh\s+pr\s+checkout|git\s+fetch\s+.*refs/pull/")

_KIND_NOTE = {
    "direct": "PR 由来の式を直接 ref に指定",
    "indirect": "step 出力経由（中身を追えないため疑わしい扱い）",
    "run": "run: 内で PR を checkout",
}
#: indirect は「追えないので疑わしい」であって確定ではない。severity で区別だけしておく。
#: ゲートとしてはどれも止める（移植元と同じ挙動）。
_KIND_SEVERITY = {"direct": "High", "indirect": "Medium", "run": "High"}


def triggers(doc: dict) -> set:
    on = doc.get("on", doc.get(True))   # YAML の on: は True に化ける
    if on is None:
        return set()
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return set(on)
    if isinstance(on, dict):
        return set(on.keys())
    return set()


def steps_of(doc: dict):
    for jname, job in (doc.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        for st in (job.get("steps") or []):
            if isinstance(st, dict):
                yield jname, st


def evaluate(path: str, text: str, include_indirect: bool = True) -> list[Finding]:
    doc = safe_load(text)
    if not isinstance(doc, dict):
        return []
    priv = triggers(doc) & PRIV
    if not priv:
        return []

    trig = sorted(priv)
    out: list[Finding] = []
    for jname, st in steps_of(doc):
        uses = str(st.get("uses") or "")
        run = str(st.get("run") or "")
        with_ = st.get("with") or {}
        ref = str(with_.get("ref") or "")

        if uses.startswith("actions/checkout") and ref:
            kind = None
            if UNTRUSTED.search(ref):
                kind = "direct"
            elif INDIRECT.search(ref):
                kind = "indirect"
            if kind and (kind != "indirect" or include_indirect):
                line = line_of(with_, "ref") or line_of(st, "uses")
                out.append(_finding(path, text, line, jname, kind, ref.strip(), trig))

        if RUN_CHECKOUT.search(run):
            line = _run_line(st, run)
            detail = run.strip().splitlines()[0][:80]
            out.append(_finding(path, text, line, jname, "run", detail, trig))
    return out


def _run_line(step, run: str) -> int:
    """run: ブロックの中で実際に checkout している行を指す。

    run: は複数行のことが多く、ブロックの先頭を指すと指紋の材料が
    「|」や無関係な 1 行目になってしまう。
    """
    base = line_of(step, "run")
    if not base:
        return 0
    for offset, line in enumerate(run.splitlines()):
        if RUN_CHECKOUT.search(line):
            # run: の値が次の行から始まる想定（run: | / run: >-）。
            # 1 行形式なら base 行そのものに当たる。
            return base + offset + (0 if len(run.splitlines()) == 1 else 1)
    return base


def _finding(path: str, text: str, line: int, job: str, kind: str, detail: str, trig: list[str]) -> Finding:
    src = source_line(text, line) or detail
    return Finding(
        rule=RULE,
        path=path,
        line=line,
        severity=_KIND_SEVERITY[kind],
        job=job,
        gate=GATE_B,
        kind="own",
        subkind=kind,
        source=src,
        desc=f"{'/'.join(trig)} の特権文脈で PR 側のコードを checkout している"
             f"（{_KIND_NOTE[kind]}）",
        url="https://codeql.github.com/codeql-query-help/actions/actions-untrusted-checkout-critical/",
        triggers=trig,
        detail=detail,
    )

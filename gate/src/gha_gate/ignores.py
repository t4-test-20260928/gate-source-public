"""ignore の規約（1-4）。

D2（2026-09-29 確定）により、PR ゲートは repo 側の ignore を尊重する。
zizmor 由来の検出は zizmor 自身が落とすので、エンジンは `--no-ignores` を
渡さないだけでよい。自前ルールには zizmor と同じ形の規約を実装する。

書式（自前ルール用。zizmor と衝突しないよう名前空間を分ける）:

    ref: ${{ github.head_ref }}   # gha-gate: ignore[untrusted-checkout] reason=到達不能 until=2026-12-31 ticket=ABC-123

- 検出行の行末コメントだけを見る（zizmor のインライン ignore と同じ位置）
- `reason=` と `until=` は必須。`ticket=` は任意
- `until` が切れたものは無視する ＝ 検出が復活する

さらに運用設計 §3.3「理由・期限が無い ignore は別ルールとして落とす」を実装する。
これは `# zizmor:` 側にも当てる。zizmor は reason/until を解さずに抑止してしまうので、
中央から見えるのはこの lint だけになる。

    invalid-ignore   reason / until が無い、または until が日付として読めない
    expired-ignore   until が切れている（`# zizmor:` 側のみ。自前側は検出が復活するので出さない）

lint を止めたいときは scan に `--no-ignore-lint` を渡す。
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import re

from .model import GATE_C, Finding, normalize_source

NS_ZIZMOR = "zizmor"
NS_SELF = "gha-gate"

RULE_INVALID_IGNORE = "invalid-ignore"
RULE_EXPIRED_IGNORE = "expired-ignore"

_DIRECTIVE = re.compile(
    r"#\s*(?P<ns>zizmor|gha-gate)\s*:\s*ignore\[(?P<rules>[^\]]*)\](?P<rest>.*)$"
)
_KV = re.compile(
    r"(?P<key>[A-Za-z_][A-Za-z0-9_-]*)="
    r"(?P<val>\"[^\"]*\"|'[^']*'|.*?)"
    r"(?=\s+[A-Za-z_][A-Za-z0-9_-]*=|\s*$)"
)


@dataclasses.dataclass
class Directive:
    namespace: str
    rules: list[str]
    line: int
    raw: str
    reason: str = ""
    until: _dt.date | None = None
    ticket: str = ""
    errors: list[str] = dataclasses.field(default_factory=list)

    @property
    def valid(self) -> bool:
        return not self.errors

    def expired(self, today: _dt.date) -> bool:
        return self.until is not None and self.until < today

    def covers(self, rule: str) -> bool:
        return rule in self.rules or "*" in self.rules


def _unquote(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    return v


def parse_line(text: str, line_no: int) -> Directive | None:
    m = _DIRECTIVE.search(text)
    if not m:
        return None
    rules = [r.strip() for r in m.group("rules").split(",") if r.strip()]
    d = Directive(
        namespace=m.group("ns"),
        rules=rules,
        line=line_no,
        raw=normalize_source(m.group(0)),
    )
    kv = {m2.group("key"): _unquote(m2.group("val")) for m2 in _KV.finditer(m.group("rest"))}
    d.reason = kv.get("reason", "")
    d.ticket = kv.get("ticket", "")
    if not rules:
        d.errors.append("ignore[...] にルール名が無い")
    if not d.reason:
        d.errors.append("reason= が無い")
    raw_until = kv.get("until", "")
    if not raw_until:
        d.errors.append("until= が無い")
    else:
        try:
            d.until = _dt.date.fromisoformat(raw_until)
        except ValueError:
            d.errors.append(f"until= が日付として読めない（{raw_until!r} / YYYY-MM-DD）")
    return d


def parse(text: str) -> dict[int, Directive]:
    """ファイル本文から行番号 → Directive を作る。"""
    out: dict[int, Directive] = {}
    for i, raw in enumerate(text.splitlines(), start=1):
        d = parse_line(raw, i)
        if d is not None:
            out[i] = d
    return out


def lint(path: str, text: str, today: _dt.date) -> list[Finding]:
    """書式の壊れた ignore / 期限切れの zizmor ignore を検出として返す。"""
    findings: list[Finding] = []
    for line_no, d in sorted(parse(text).items()):
        src = text.splitlines()[line_no - 1]
        if d.errors:
            findings.append(
                Finding(
                    rule=RULE_INVALID_IGNORE,
                    path=path,
                    line=line_no,
                    severity="High",
                    gate=GATE_C,
                    kind="lint",
                    source=src,
                    desc="理由・期限のない ignore は認めない（運用設計 §3.3）: "
                    + " / ".join(d.errors),
                    detail=d.raw,
                )
            )
        elif d.namespace == NS_ZIZMOR and d.expired(today):
            findings.append(
                Finding(
                    rule=RULE_EXPIRED_IGNORE,
                    path=path,
                    line=line_no,
                    severity="High",
                    gate=GATE_C,
                    kind="lint",
                    source=src,
                    desc=f"ignore の期限が切れている（until={d.until}）。"
                    "zizmor 側は期限を解さないので、この lint が切れたことを知る唯一の口",
                    detail=d.raw,
                )
            )
    return findings


def apply(
    findings: list[Finding],
    text: str,
    today: _dt.date,
    respect: bool = True,
) -> tuple[list[Finding], list[Finding]]:
    """自前ルールの検出に ignore を適用し、(残るもの, 抑止されたもの) を返す。

    zizmor 由来の検出はここに来ない。zizmor 自身が落としているため。

    `respect=False` は定期スキャン（`--no-ignores`）用。抑止せずに残したうえで
    「ignore が書かれていた」ことを suppression に記録する。運用設計 §3.3 の
    非対称 —— PR ゲートは尊重、定期スキャンは無視 —— は、zizmor 側だけでなく
    自前ルール側でも成立させないと、中央から抑止量が見えなくなる。
    """
    directives = parse(text)
    kept: list[Finding] = []
    suppressed: list[Finding] = []
    for f in findings:
        d = directives.get(f.line)
        if d is None or d.namespace != NS_SELF or not d.covers(f.rule) or not d.valid:
            kept.append(f)
            continue
        if not respect:
            f.suppression = {
                "state": "disregarded",
                "reason": d.reason,
                "until": d.until.isoformat() if d.until else "",
                "ticket": d.ticket,
            }
            kept.append(f)
            continue
        if d.expired(today):
            f.suppression = {
                "state": "expired",
                "reason": d.reason,
                "until": d.until.isoformat() if d.until else "",
                "ticket": d.ticket,
            }
            kept.append(f)
            continue
        f.suppressed = True
        f.suppression = {
            "state": "suppressed",
            "namespace": d.namespace,
            "reason": d.reason,
            "until": d.until.isoformat() if d.until else "",
            "ticket": d.ticket,
        }
        suppressed.append(f)
    return kept, suppressed

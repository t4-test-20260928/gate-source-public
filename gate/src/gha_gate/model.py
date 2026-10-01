"""findings の正規化スキーマと指紋（1-2）。

指紋の定義は運用設計 §3.5 に合わせる。

    fingerprint = sha256(rule + path + 該当行の正規化テキスト)

行番号をキーにしない。リファクタで行が動いても例外は効き続け、中身が変わったら
例外が自動で外れる（`@v35` → `@v46` に直したら例外は無効になる＝正しい挙動）。
"""

from __future__ import annotations

import dataclasses
import hashlib
import re
from typing import Any

SCHEMA_VERSION = "1"

# gate A = zizmor 由来 / gate B = 自前ルール / gate C = ゲート自身の lint
GATE_A = "A"
GATE_B = "B"
GATE_C = "C"

_WS = re.compile(r"\s+")


def normalize_source(text: str) -> str:
    """指紋に使う「該当行の正規化テキスト」。

    空白の畳み込みだけをする。インデントの変更や整形で指紋が動かないようにしつつ、
    参照している action のバージョンのような意味のある変化は指紋に残す。
    """
    return _WS.sub(" ", (text or "").strip())


def fingerprint(rule: str, path: str, source: str) -> str:
    h = hashlib.sha256()
    h.update(rule.encode("utf-8"))
    h.update(b"\0")
    h.update(path.encode("utf-8"))
    h.update(b"\0")
    h.update(normalize_source(source).encode("utf-8"))
    return h.hexdigest()


@dataclasses.dataclass
class Finding:
    """1 件の検出。

    rule / path / line / severity / job / fingerprint が正規化スキーマの本体で、
    それ以外は出力を人が読めるものにするための付随情報。可視性が public の
    レンダリングでは rule / path / line / fingerprint 以外は落とす（1-5）。
    """

    rule: str
    path: str
    line: int
    severity: str
    job: str = ""
    gate: str = GATE_A
    kind: str = "single"          # single | paired | own | lint
    subkind: str = ""             # gate B の direct | indirect | run
    source: str = ""              # 指紋の材料になった該当行
    fingerprint: str = ""
    desc: str = ""
    url: str = ""
    partners: list[str] = dataclasses.field(default_factory=list)
    triggers: list[str] = dataclasses.field(default_factory=list)
    detail: str = ""
    annotation: str = ""
    fix: str = ""
    suppressed: bool = False
    suppression: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if not self.fingerprint:
            self.fingerprint = fingerprint(self.rule, self.path, self.source or self.detail)

    @property
    def short_fingerprint(self) -> str:
        return self.fingerprint[:12]

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        if d["suppression"] is None:
            d.pop("suppression")
        return d


@dataclasses.dataclass
class ScanStatus:
    """スキャンがどこまで見られたか（1-6）。

    「検出 0 件」と「ツールの失敗」を絶対に同じ緑にしないために、レンダラが
    判断できるだけの情報をここに残す。
    """

    ok: bool = True
    reason: str = "ok"            # ok | off | no-input | skipped | degraded | error
    zizmor_rc: int | None = None
    degraded: list[str] = dataclasses.field(default_factory=list)
    message: str = ""

    @property
    def is_error(self) -> bool:
        return self.reason == "error"

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class Report:
    phase: str
    status: ScanStatus
    findings: list[Finding] = dataclasses.field(default_factory=list)
    suppressed: list[Finding] = dataclasses.field(default_factory=list)
    target: dict[str, Any] = dataclasses.field(default_factory=dict)
    scope: dict[str, Any] = dataclasses.field(default_factory=dict)
    engine: dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "engine": self.engine,
            "target": self.target,
            "phase": self.phase,
            "scope": self.scope,
            "status": self.status.to_dict(),
            "summary": {
                "findings": len(self.findings),
                "suppressed": len(self.suppressed),
                "by_rule": _count(self.findings),
            },
            "findings": [f.to_dict() for f in self.findings],
            "suppressed": [f.to_dict() for f in self.suppressed],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Report":
        status = ScanStatus(**d.get("status", {}))
        return cls(
            phase=d["phase"],
            status=status,
            findings=[_finding(x) for x in d.get("findings", [])],
            suppressed=[_finding(x) for x in d.get("suppressed", [])],
            target=d.get("target", {}),
            scope=d.get("scope", {}),
            engine=d.get("engine", {}),
        )


def _finding(d: dict[str, Any]) -> Finding:
    fields = {f.name for f in dataclasses.fields(Finding)}
    return Finding(**{k: v for k, v in d.items() if k in fields})


def _count(findings: list[Finding]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        out[f.rule] = out.get(f.rule, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: (-kv[1], kv[0])))

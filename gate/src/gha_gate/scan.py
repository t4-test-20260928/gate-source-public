"""スキャンの本体 — zizmor の起動、自前ルール、ignore、スコープ判定をまとめる。"""

from __future__ import annotations

import datetime as _dt
import os
from pathlib import Path

from . import ENGINE_NAME, __version__
from . import ignores, phase as phase_mod, runner, scope as scope_mod
from .model import Finding, Report, ScanStatus
from .rules import untrusted_checkout, zizmor_gate


def scan(
    root: str | Path,
    *,
    phase: str = phase_mod.ERROR,
    changed_files: list[str] | None = None,
    repo: str = "",
    visibility: str = "private",
    no_ignores: bool = False,
    no_config: bool = False,
    ignore_lint: bool = True,
    include_indirect: bool = True,
    extra_rules: tuple[str, ...] = (),
    zizmor_findings: list[dict] | None = None,
    today: _dt.date | None = None,
    env: dict | None = None,
) -> Report:
    """判定を走らせて Report を返す。例外は投げず、失敗も status に載せる。

    `zizmor_findings` を渡すと zizmor を起動せずにその出力を使う。回帰テストと、
    「zizmor は別ステップで回す」構成のための口。
    """
    root = Path(root)
    today = today or _dt.date.today()
    phase = phase_mod.normalize(phase)

    engine = {
        "name": ENGINE_NAME,
        "version": __version__,
        "zizmor": runner.version(),
        "include_indirect": include_indirect,
        "no_ignores": no_ignores,
        "no_config": no_config,
        "ignore_lint": ignore_lint,
    }
    target = {"root": str(root), "repo": repo, "visibility": visibility}

    if not phase_mod.RUNS_AUDIT[phase]:
        return Report(
            phase=phase,
            status=ScanStatus(ok=True, reason="off", message="phase=off"),
            target=target,
            scope={"mode": "off", "files": [], "skip": True, "reason": "phase=off"},
            engine=engine,
        )

    sel = scope_mod.select(root, changed_files)
    if sel["skip"]:
        return Report(
            phase=phase,
            status=ScanStatus(ok=True, reason="skipped", message=sel["reason"]),
            target=target,
            scope=sel,
            engine=engine,
        )

    # ---- gate A: zizmor
    findings: list[Finding] = []
    status = ScanStatus()
    if zizmor_findings is None:
        inputs = sel["files"] if sel["mode"] == "changed-files" else None
        res = runner.run(
            root, inputs, no_ignores=no_ignores, no_config=no_config,
            env=env or os.environ.copy(),
        )
        status = ScanStatus(
            ok=res.ok, reason=res.reason, zizmor_rc=res.rc,
            degraded=list(res.degraded), message=res.message,
        )
        if not res.ok:
            return Report(phase=phase, status=status, target=target, scope=sel, engine=engine)
        zizmor_findings = res.findings

    findings += zizmor_gate.evaluate(zizmor_findings, extra_rules=extra_rules)

    # ---- gate B / gate C: 自前ルールと ignore
    suppressed: list[Finding] = []
    for rel in sel["workflows"]:
        path = root / rel
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        own = untrusted_checkout.evaluate(rel, text, include_indirect=include_indirect)
        kept, dropped = ignores.apply(own, text, today, respect=not no_ignores)
        findings += kept
        suppressed += dropped
        if ignore_lint:
            findings += ignores.lint(rel, text, today)

    findings.sort(key=lambda f: (f.path, f.line, f.rule))
    suppressed.sort(key=lambda f: (f.path, f.line, f.rule))
    return Report(
        phase=phase, status=status, findings=findings, suppressed=suppressed,
        target=target, scope=sel, engine=engine,
    )

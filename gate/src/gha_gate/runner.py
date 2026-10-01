"""zizmor の起動と、その失敗の切り分け（1-6 / 差分 #5）。

zizmor の exit code:

    0      監査できた（検出の有無は --no-exit-codes のため code に出ない）
    3      入力が無い
    それ以外  監査が成立していない

「検出 0 件」と「ツールの失敗」を絶対に同じ緑にしない。ここでは判定だけを行い、
落とすかどうかは render に渡す（scan は常に exit 0 で JSON を書く）。

online 監査の扱い（差分 #5 / D4）:
  対象 repo 文脈の GITHUB_TOKEN では他 repo の private action を読めず、
  zizmor が `fatal: no audit was performed` で落ちる（実測で一定数のリポジトリが該当）。
  これはゲートの故障ではなく到達範囲の問題なので fail-open にする。
  具体的には --offline で引き直し、impostor-commit / known-vulnerable-actions は
  判定できていない旨を status.degraded に残す（中央記録は T3 側の担当）。
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from . import ZIZMOR_PINNED_VERSION
from .rules.zizmor_gate import ONLINE_ONLY

ZIZMOR_NO_INPUT_RC = 3

#: 参照先 action が引けずに online 監査が成立しなかったときの実測シグネチャ。
#  （全数スキャンのログから採取）
_ONLINE_FAILURE = re.compile(
    r"missing or you have no access"
    r"|couldn't list branches for"
    r"|can't access [\w.\-]+/[\w.\-]+"
    r"|rate limit",
    re.I,
)

_TOKEN = re.compile(r"(token=)[A-Za-z0-9_\-]+")


def redact(text: str) -> str:
    return _TOKEN.sub(r"\1REDACTED", text)


def base_argv(no_ignores: bool, no_config: bool, offline: bool) -> list[str]:
    """判定条件は設計案の実装と同じにする。

    PR ゲートは --no-ignores を付けない（D2: repo 側の ignore を尊重する）。
    定期スキャンは --no-ignores --no-config を付けて、抑止された分を中央から数える。
    """
    argv = [
        "zizmor",
        "--persona=auditor",
        "--min-confidence=low",
        "--collect=all",
        "--no-exit-codes",
        "--no-progress",
        "--format=json-v1",
    ]
    if no_ignores:
        argv.append("--no-ignores")
    if no_config:
        argv.append("--no-config")
    if offline:
        argv.append("--offline")
    return argv


class ZizmorResult:
    def __init__(self) -> None:
        self.findings: list[dict] = []
        self.rc: int | None = None
        self.ok = True
        self.reason = "ok"          # ok | no-input | degraded | error
        self.degraded: list[str] = []
        self.message = ""


def version() -> str | None:
    if shutil.which("zizmor") is None:
        return None
    try:
        out = subprocess.run(
            ["zizmor", "--version"], capture_output=True, text=True, timeout=30
        ).stdout
    except Exception:
        return None
    m = re.search(r"(\d+\.\d+\.\d+)", out)
    return m.group(1) if m else None


def run(
    root: str | Path,
    inputs: list[str] | None = None,
    *,
    no_ignores: bool = False,
    no_config: bool = False,
    env: dict | None = None,
    timeout: int = 600,
) -> ZizmorResult:
    """zizmor を起動して json-v1 を読む。fail-open の判断までをここで行う。"""
    result = ZizmorResult()
    root = Path(root)

    if shutil.which("zizmor") is None:
        result.ok = False
        result.reason = "error"
        result.message = "zizmor が PATH に無い"
        return result

    got = version()
    if got and got != ZIZMOR_PINNED_VERSION:
        result.degraded.append(
            f"zizmor {got} で実行した（判定を確認済みなのは {ZIZMOR_PINNED_VERSION}）"
        )

    targets = inputs if inputs else ["."]

    proc = _invoke(base_argv(no_ignores, no_config, offline=False), targets, root, env, timeout)
    if proc.returncode == ZIZMOR_NO_INPUT_RC:
        result.rc = proc.returncode
        result.reason = "no-input"
        result.message = "監査対象の workflow / action 定義が無い"
        return result

    if proc.returncode != 0:
        stderr = redact(proc.stderr or "")
        if not _ONLINE_FAILURE.search(stderr):
            result.rc = proc.returncode
            result.ok = False
            result.reason = "error"
            result.message = f"zizmor が exit {proc.returncode}（検出 0 件ではない）\n" + _tail(stderr)
            return result

        # fail-open: 参照先が引けなかっただけ。offline で引き直す。
        offline_proc = _invoke(
            base_argv(no_ignores, no_config, offline=True), targets, root, env, timeout
        )
        if offline_proc.returncode not in (0, ZIZMOR_NO_INPUT_RC):
            result.rc = offline_proc.returncode
            result.ok = False
            result.reason = "error"
            result.message = (
                f"online 監査が失敗し、offline でも exit {offline_proc.returncode}\n"
                + _tail(redact(offline_proc.stderr or ""))
            )
            return result
        result.rc = offline_proc.returncode
        result.reason = "degraded"
        result.degraded.append(
            "online 監査が成立しなかったため offline で判定した。"
            + " / ".join(sorted(ONLINE_ONLY))
            + " は判定できていない"
        )
        result.message = _tail(stderr, 5)
        proc = offline_proc
        if proc.returncode == ZIZMOR_NO_INPUT_RC:
            return result

    result.rc = proc.returncode
    try:
        parsed = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError as e:
        result.ok = False
        result.reason = "error"
        result.message = f"zizmor の出力が JSON として読めない: {e}"
        return result
    result.findings = parsed if isinstance(parsed, list) else []
    return result


def _invoke(argv: list[str], targets: list[str], root: Path, env: dict | None, timeout: int):
    return subprocess.run(
        argv + targets,
        cwd=str(root),
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
    )


def _tail(text: str, lines: int = 20) -> str:
    return "\n".join((text or "").strip().splitlines()[-lines:])

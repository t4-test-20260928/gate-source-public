"""判定スコープ（D3 / 実装は plan §2.1）。

D3（2026-09-29 確定）: PR ゲートは変更ファイル限定。workflow / action 定義の変更が
無い PR はスキップして success で返す。

required workflow は `on:` の `paths:` フィルタを全部無視する（実測）。
つまりスキップ判定は job の中で自分で書くことになる。順序はこう:

    ① PR の変更ファイル一覧を取る   gh api /repos/{owner}/{repo}/pulls/{n}/files --paginate
    ② 対象パスに 1 件も当たらない → その場で success でリターン
    ③ 当たったファイルだけを zizmor に渡す
    ④ 自前ルールも同じファイル集合だけを読む

なぜ「入力を絞る」で結果が変わらないか — 判定単位が最初からファイル内で閉じているため。
単独ルールは finding 単位、同居ルールは同一 workflow ファイル内でのみ成立し、
自前の untrusted-checkout も 1 ファイルの中で trigger と checkout が揃うかを見ている。
findings を後から絞るのではなく、zizmor への入力そのものを絞ってよい。

原理的な穴（呼び出し側だけが変わった PR / 既存の抵触に触れない PR）は、PR ゲートで
埋める穴ではなく定期スキャンの担当範囲。運用設計 §4.1 の R1 に乗る。
"""

from __future__ import annotations

import os
from pathlib import Path

#: 対象パス。`.github/zizmor.yml` は意図的に含めない
#  （含めると ignore を足しただけの PR でゲートが走る。D2 と整合しない）
WORKFLOW_DIR = ".github/workflows/"
ACTION_DIR = ".github/actions/"
ACTION_FILENAMES = ("action.yml", "action.yaml")
YAML_SUFFIXES = (".yml", ".yaml")

TARGET_DESCRIPTION = (
    f"{WORKFLOW_DIR}**  {ACTION_DIR}**  **/action.yml  **/action.yaml"
)


def normalize_path(path: str) -> str:
    """`./x` や `x` の揺れを吸収する。`.lstrip("./")` は先頭の文字を食うので使わない
    （".github/..." が "github/..." になる）。"""
    p = path.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def is_target(path: str) -> bool:
    p = normalize_path(path)
    if p.startswith(WORKFLOW_DIR) and p.endswith(YAML_SUFFIXES):
        return True
    if p.startswith(ACTION_DIR) and p.endswith(YAML_SUFFIXES):
        return True
    return os.path.basename(p) in ACTION_FILENAMES


def read_changed_files(path: str | Path) -> list[str]:
    """`gh api ... --jq '.[].filename'` の出力（1 行 1 パス）を読む。"""
    raw = Path(path).read_text(encoding="utf-8", errors="replace")
    return [line.strip() for line in raw.splitlines() if line.strip()]


def select(root: str | Path, changed_files: list[str] | None) -> dict:
    """スキャン対象を決める。

    返り値の `skip` が True なら、判定を一切走らせずに success で返してよい。
    """
    root = Path(root)
    if changed_files is None:
        files = sorted(
            str(p.relative_to(root))
            for p in (root / WORKFLOW_DIR).glob("*.y*ml")
            if p.is_file()
        )
        return {
            "mode": "full",
            "files": files,
            "workflows": files,
            "skip": False,
            "reason": "",
        }

    targets = [f for f in changed_files if is_target(f)]
    # 削除だけの PR — 変更ファイルが checkout 後に存在しない。
    # 存在するものだけに絞ってから渡す（絞った結果 0 件ならスキップと同じ扱い）。
    existing = [f for f in targets if (root / f).is_file()]
    workflows = [f for f in existing if normalize_path(f).startswith(WORKFLOW_DIR)]
    if not existing:
        if targets:
            reason = "対象ファイルは変更されているが、すべて削除済み"
        else:
            reason = "workflow / action 定義の変更が無い"
        return {
            "mode": "changed-files",
            "files": [],
            "workflows": [],
            "skip": True,
            "reason": reason,
            "changed": len(changed_files),
        }
    return {
        "mode": "changed-files",
        "files": sorted(existing),
        "workflows": sorted(workflows),
        "skip": False,
        "reason": "",
        "changed": len(changed_files),
    }

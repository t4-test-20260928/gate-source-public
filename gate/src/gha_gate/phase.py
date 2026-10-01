"""Phase — ゲートの実行モード（`PHASE-01` 〜 `PHASE-03`）。

エンジンの入力を 1 個変えるだけで挙動が切り替わるようにする。ruleset を作り直したり
workflow を配り直したりせずに段階適用とロールバックができる状態を作るのが目的。

    off      チェックしない。zizmor も自前ルールも走らせない
    notice   判定は全部走らせる。結果は出すが、検出を理由に落とすことはしない
    error    判定を走らせ、検出があれば落とす

phase 名は、その phase が出す annotation の種別（`::notice` / `::error`）と同じ語にしてある。

実際に merge を止めるかどうかは、この値と Organization ruleset の enforcement
（evaluate / active）の積で決まる。エンジンは「落とす判断」までしか持たない。

    ruleset\\phase |  off   | notice |  error
    --------------+--------+--------+--------------------------
    evaluate      |  無風  |  無風  |  赤くなるが merge はできる
    active        |  無風  |  無風  |  merge が止まる

注意: 「検出があるから落とす」と「エンジンが壊れたから落とす」は別物として扱う
（`PHASE-07`）。前者は phase に従うが、後者は phase に関係なく EXIT_ENGINE_ERROR。
notice が握り潰すのは検出だけで、ツールの失敗は握り潰さない。

phase の `error` と、エンジン故障を表す `status.reason = "error"`（`PHASE-12`）は
**別物**。前者は「検出で落とす設定」、後者は「エンジンが壊れた」。
"""

from __future__ import annotations

OFF = "off"
NOTICE = "notice"
ERROR = "error"

ALL = (OFF, NOTICE, ERROR)

#: 判定を実行するか
RUNS_AUDIT = {OFF: False, NOTICE: True, ERROR: True}

#: 検出があったときに落とすか
BLOCKS_ON_FINDINGS = {OFF: False, NOTICE: False, ERROR: True}

#: GitHub Actions のワークフローコマンド（annotation）の種別
ANNOTATION_LEVEL = {OFF: None, NOTICE: "notice", ERROR: "error"}

EXIT_PASS = 0
EXIT_FINDINGS = 1
EXIT_ENGINE_ERROR = 2


def normalize(value: str) -> str:
    v = (value or "").strip().lower()
    if v not in ALL:
        raise ValueError(f"phase は {'/'.join(ALL)} のいずれか（与えられた値: {value!r}）")
    return v

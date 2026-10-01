"""判定ルール。

gate A = zizmor の json-v1 出力に対する判定（単独ルール + 同居ルール）
gate B = 自前ルール（特権 trigger での PR head checkout）
gate C = ignore の lint（ignores.py）
"""

from . import untrusted_checkout, zizmor_gate  # noqa: F401

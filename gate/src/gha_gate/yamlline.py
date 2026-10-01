"""行番号を保持したまま YAML を読む。

自前ルール（gate B）の検出に行番号を付けるために要る。サンプル実装は
`yaml.safe_load` で読んでいたため行番号が取れず、検出の line が全部 0 だった。
指紋は「該当行の正規化テキスト」を材料にするので、行が特定できないと指紋が作れない。

`yaml.safe_load` と同じ結果を返し、mapping だけ dict のサブクラスにして
「その mapping の開始行」と「キーごとの行」を持たせる。判定ロジック側は通常の
dict として扱えるので、移植元との差が出ない。
"""

from __future__ import annotations

import yaml


class LineDict(dict):
    """開始行とキーごとの行（いずれも 1 始まり）を持つ dict。"""

    __slots__ = ("line", "key_lines")

    def __init__(self, *args, line: int = 0, key_lines: dict | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.line = line
        self.key_lines = key_lines or {}


class _LineLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader: yaml.SafeLoader, node: yaml.MappingNode) -> LineDict:
    loader.flatten_mapping(node)
    pairs = loader.construct_pairs(node, deep=True)
    key_lines: dict = {}
    for (key_node, _value_node), (key, _value) in zip(node.value, pairs):
        try:
            key_lines[key] = key_node.start_mark.line + 1
        except TypeError:      # ハッシュ不能なキー。行が引けなくても判定は続ける
            pass
    return LineDict(pairs, line=node.start_mark.line + 1, key_lines=key_lines)


_LineLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping
)


def line_of(obj: object, key: object = None, default: int = 0) -> int:
    """mapping の開始行、または mapping 内の特定キーの行を返す。"""
    if key is not None:
        lines = getattr(obj, "key_lines", None)
        if lines:
            got = lines.get(key)
            if got:
                return got
    return getattr(obj, "line", default)


def safe_load(text: str):
    """行番号付きで読む。読めなければ None（呼び出し側は素通しする）。"""
    try:
        return yaml.load(text, Loader=_LineLoader)
    except Exception:
        return None


def source_line(text: str, line: int) -> str:
    """1 始まりの行番号で元テキストの 1 行を返す。指紋の材料。"""
    if line <= 0:
        return ""
    lines = text.splitlines()
    if line > len(lines):
        return ""
    return lines[line - 1]

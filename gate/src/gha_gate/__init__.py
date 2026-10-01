"""GitHub Actions セキュリティゲート — 判定エンジン。

仕様の正本と、判定の根拠になった実測値は運用側の記録（docs/spec.md）にある。
このパッケージのコメントには具体的な実測値を書かない（公開するため）。

このパッケージは「判定」だけを持つ。GitHub Actions への配送（entry / reusable /
composite action）と ruleset は T2 の担当で、ここには入れない。
"""

__version__ = "0.1.0"
ENGINE_NAME = "gha-gate"

# 判定の再現性のため、対応を確認した zizmor を固定する。
# 変えるときは回帰テストを回し、基準スキャンの結果と一致することを確認する。
ZIZMOR_PINNED_VERSION = "1.30.1"

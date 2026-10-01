# gha-gate — GitHub Actions セキュリティゲートの判定エンジン

**このディレクトリは `t4-test-20260928/gate-source`（private）からのミラー。**
直接編集しない。変更は gate-source 側で行い、そこから同期する。

public に置いてあるのは、**public リポジトリをゲートするには source repo が public で
ある必要がある**ため（private source → public / internal target は GitHub の仕様で不可）。

```
action.yml        エンジンの配送口（composite action）
requirements.txt  zizmor / PyYAML（バージョン固定）
src/gha_gate/     判定本体
```

## 使う

```yaml
- uses: actions/checkout@<sha>
- uses: t4-test-20260928/gate-source-public/gate@<sha>
  with:
    phase: notice        # off / notice / error
    visibility: ${{ github.event.repository.visibility }}
```

判定コードは**この repo の固定 ref から**来る。対象リポジトリからは読まない。
`$GITHUB_ACTION_PATH` が指すのは checkout された action 自身であって、対象リポジトリの
作業ツリーではない。対象リポジトリのファイルは `root` の下に「解析対象」としてしか現れない。

## 中身について

判定の根拠になった実測値（適用対象の規模、検出件数など）は**このリポジトリには置いていない**。
運用側の記録にある。

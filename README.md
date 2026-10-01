# gate-source-public

GitHub Actions セキュリティゲートの **public 側 source repo**（検証用）。

`t4-test-20260928` は検証用の sandbox org。本物の仕事はしない。

## なぜ public 側が要るか

required workflow と composite action は、**private な source repo から public /
internal の target repo へは配送できない**（GitHub の仕様）。public リポジトリを
ゲートするには、source repo も public である必要がある。

## 中身

```
gate/                        判定エンジン（gate-source からのミラー）
.github/workflows/gate.yml   entry workflow。required workflow として配送される
.github/workflows/insecure-sample.yml
                             ⚠ わざと脆弱に書いたテスト用サンプル。実行されない
```

> **⚠ `insecure-sample.yml` は意図的に非準拠に書いたテスト用のファイル。**
> セキュリティゲートがそれを検出できるかを確かめるためだけに置いている。
> 他のリポジトリにコピーしないこと。実行されないよう三重に止めてある
> （Actions の設定 / 発火しない `branches:` フィルタ / job は `echo` のみ）。

仕様の正本は `t4-test-20260928/gate-source`（private）の `docs/spec.md`。

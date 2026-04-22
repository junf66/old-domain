# 中古ドメイン発掘ツール

expireddomains.net の CSV を入力に、Ahrefs API と Wayback Machine API でドメインを評価し、
GitHub Pages で一覧・ソート・絞り込みできる静的ダッシュボードを出力するツールです。

## 全体像

```
[expireddomains.net で手動CSVダウンロード]
            ↓
[data/input/ に置く]
            ↓
[analyze.py 実行]  ← Ahrefs API + Wayback Machine API
            ↓
[docs/data.json 更新]
            ↓
[GitHub Pages で一覧表示・ソート・絞り込み]
```

## ディレクトリ構成

```
old-domain/
├── data/
│   ├── input/          # expireddomains.net の CSV をここに置く
│   └── output/         # 処理済みデータ(タイムスタンプ付きスナップショット)
├── scripts/
│   ├── analyze.py
│   ├── ahrefs_client.py
│   └── wayback_client.py
├── docs/
│   ├── index.html      # ダッシュボード(単一HTML、CDN経由で jQuery + DataTables)
│   └── data.json       # analyze.py が書き出す一覧データ
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

## セットアップ

```bash
# 1. 依存関係インストール
pip install -r requirements.txt

# 2. Ahrefs API キーを設定
cp .env.example .env
# .env を開いて AHREFS_API_KEY=xxxxx を記入
```

## expireddomains.net からの CSV エクスポート手順

1. [expireddomains.net](https://www.expireddomains.net/) にログイン。
2. 検索条件(TLD、DR、価格、日本語キーワード等)を指定。
3. 結果一覧の右上 **[Export]** → **CSV (semicolon separated)** を選択して
   ダウンロード。
4. ダウンロードした `.csv` を **本リポジトリの `data/input/` に置く**。
   - 複数ファイルを置いた場合、`analyze.py` は **最も新しい CSV**
     を自動で選択します。
5. CSV には最低限 `Domain` 列が必要です
   (`domain` / `URL` / `url` でも可)。

## 実行

```bash
# 通常実行(Ahrefs + Wayback を叩く)
python scripts/analyze.py

# 特定ファイルを指定
python scripts/analyze.py --input data/input/my-export.csv

# API を叩かずにダミーデータで動作確認
python scripts/analyze.py --dry-run
```

実行すると以下が更新されます:

- `docs/data.json` ... ダッシュボードが読む最新データ
- `data/output/data-YYYYMMDDTHHMMSSZ.json` ... タイムスタンプ付きの生データ
  (`.gitignore` により commit されない)

## ダッシュボードの閲覧

### ローカル

```bash
python -m http.server 8000 -d docs
# → http://localhost:8000/ を開く
```

### GitHub Pages

1. GitHub でリポジトリを作成 → push。
2. Settings → Pages → Source を **Deploy from a branch**、Branch を
   `main` / `/docs` に設定。
3. 数十秒後、公開URL (`https://<user>.github.io/<repo>/`) で閲覧可能。

## ダッシュボード機能

- 列:ドメイン / スコア / DR / 参照ドメイン / 運用年数 / 日本語履歴 /
  スパム / Waybackリンク / Ahrefsリンク
- 列クリックでソート(デフォルト:スコア降順)
- 上部フィルタ:DR 下限スライダ、参照ドメイン下限スライダ、
  日本語履歴ありのみ、スパムなしのみ
- スコアに応じた背景色(80+ 緑、60-80 黄、<60 グレー)

## スコアリング

| 要素 | 配点 | 計算式 |
|---|---|---|
| DR | 40 | `min(DR, 100) × 0.4` |
| 参照ドメイン数 | 20 | `min(log10(refdomains+1) × 7, 20)` |
| 運用年数(Waybackベース) | 15 | `min(年数 × 2, 15)` |
| 日本語コンテンツ履歴 | 15 | Waybackスナップで日本語/.jp 検出=15、なし=0 |
| **スパム減点** | -50 | アンカーに `casino / porn / viagra / カジノ / アダルト / 出会い / 副業` 等が1つでもあれば -50 |

スパムキーワードは `scripts/analyze.py` の `SPAM_KEYWORDS` で編集できます。

## API

### Ahrefs v3

- `subscription-info/limits-and-usage` ... 実行前にクレジット残量を表示
- `batch-analysis/batch-analysis` ... 最大100件/回で DR・参照ドメイン数・
  オーガニックKW・オーガニックトラフィックを取得(コスト効率◎)
- `site-explorer/anchors` ... 上位20件のアンカーテキスト
  (`mode=domain`, `order_by=refdomains:desc`)

### Wayback Machine CDX

- `http://web.archive.org/cdx/search/cdx` ... 無料・認証不要
- スナップショット履歴から初回日/総数/日本語URL履歴を判定
- ドメイン間に 0.5 秒スリープ(マナー)

## ライセンス

社内利用を想定した未公開スクリプトです。再配布等は元オーナーに確認してください。

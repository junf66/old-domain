# 中古ドメイン精査ツール

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

## かんたん利用(ブラウザだけで完結・推奨)

PCに何もインストールせず、ブラウザ操作だけで使えます。

### 1回だけやる準備

1. **APIキーを登録**
   - GitHub のリポジトリで **Settings → Secrets and variables → Actions**
   - **New repository secret** をクリック
   - **Name**: `AHREFS_API_KEY` / **Value**: Ahrefs の API キーを貼る → **Add secret**
2. **Pages を有効化**
   - **Settings → Pages**
   - **Source**: `Deploy from a branch`
   - **Branch**: `main` / フォルダ `/docs` を選択 → **Save**
   - 公開URLが表示される(例: `https://junf66.github.io/old-domain/`)

### 毎回やる操作(これだけ)

1. expireddomains.net から CSV をダウンロード
2. GitHub のリポジトリ画面で `data/input/` を開く
3. **Add file → Upload files** で CSV をドラッグ&ドロップ → **Commit changes**
4. 数分待つと **Actions タブ**の実行が緑✅になり、ページが自動更新される
5. Pages の URL を開いて結果を閲覧

手動で再実行したい場合は **Actions タブ → Analyze domains → Run workflow** ボタン。

---

## PCで実行したい場合のセットアップ

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

## WordPress 投稿モード(Lv3 / XServer MCP 連携)

ダッシュボード右上の「WordPress投稿」タブから利用できます。
インストール処理は **XServer MCP Server** を経由する想定で、アプリ側には
MCP の呼び出しコードは入っていません(疎結合維持)。

### キュー / 結果のフォーマット

- `data/wp-install-queue.json` — 処理待ち
- `data/wp-install-results.json` — 処理結果

スキーマは `scripts/wp_runner.py` 冒頭のコメントを参照。

### `check_status`(WP検出・page_id 自動取得)

XServer不要。GitHub Actions の `WP runner (status-check)` ワークフローが
キューを消化し、結果を `data/wp-install-results.json` にコミットします。

1. ダッシュボードで対象サイトの行をチェック
2. **🔍 状態確認をキュー登録** をクリック
3. Actions タブで `WP runner (status-check)` が完了するのを待つ
4. ダッシュボードで **📥 結果を取り込む** → 編集URL / ステータス / メモが更新

### `install`(WordPress 構築)

GitHub Actions では処理せず、**ローカルAIエージェント + XServer MCP Server** に
処理させます。Web版の Claude / ChatGPT は MCP 経由のローカル実行ができないため
**使えません**(XServer 公式の制限)。

#### 1. XServer 側の準備

- 対象プラン: スタンダード / プレミアム / ビジネス
- XServerアカウントの「APIキー管理」で APIキー (`xs_...`) を発行
- 契約管理画面でサーバー名を確認(例: `xs123456.xsrv.jp`)

#### 2. AIエージェントに XServer MCP を登録

##### Claude Desktop

設定ファイル (`claude_desktop_config.json`) に追記:

- Mac:  `~/Library/Application Support/Claude/claude_desktop_config.json`
- Win:  `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "xserver": {
      "command": "npx",
      "args": ["-y", "xserver-mcp"],
      "env": {
        "XSERVER_API_KEY": "xs_xxxxxxxxxxxx",
        "XSERVER_SERVERNAME": "xs123456.xsrv.jp"
      }
    }
  }
}
```

##### Cursor

`.cursor/mcp.json` または `~/.cursor/mcp.json` に同じJSONを追加。

##### Claude Code

```bash
claude mcp add --transport stdio xserver \
  --env XSERVER_API_KEY=xs_xxxxxxxxxxxx \
  --env XSERVER_SERVERNAME=xs123456.xsrv.jp \
  -- npx -y xserver-mcp
```

##### 共通の前提

- Node.js v18 以上(`https://nodejs.org/`)
- 同じエージェントで GitHub MCP も併用すると、キュー/結果ファイルの
  読み書きまで自動化できます。GitHub MCP がない場合はチャットに結果が
  返るので、ダッシュボード側で「📥 最新を取り込む」前に手動で
  `data/wp-install-results.json` に追記してください。

#### 3. 動作確認

エージェントに次のように話しかけて応答が返ればOK:

```
サーバー情報を表示してください
ドメイン一覧を見せて
```

#### 4. 実運用フロー

1. ダッシュボードでサイトの行をチェック
2. **🚀 WPインストール** をクリック → `data/wp-install-queue.json` に
   `action: install` アイテムが追加され、ダッシュボードが**そのまま貼り付け
   可能なプロンプト**を表示
3. プロンプトを Claude Desktop / Cursor / Claude Code に貼り付け
4. エージェントが XServer MCP で「ドメイン追加 → SSL → WP簡単インストール」を実行
5. 結果が `data/wp-install-results.json` に書き込まれる
6. ダッシュボードで **📥 最新を取り込む** → 編集URL・admin情報・ステータスが反映

#### XServer MCP で使う主な機能(本ツールが叩く部分)

| 操作 | 用途 |
|---|---|
| ドメイン設定 / 追加 | サーバーにドメインを紐付け |
| SSL設定 / インストール | Let's Encrypt 有効化 |
| WordPress簡単インストール | WordPress 本体 + DB 自動構築 |

#### 結果ファイル(`data/wp-install-results.json`)に書く形

最低限こうしておくとダッシュボード側で自動マッピング:

```json
{
  "action": "install",
  "domain": "example.com",
  "ok": true,
  "login_url": "https://example.com/wp-admin/",
  "edit_url":  "https://example.com/wp-admin/post.php?post=2&action=edit",
  "admin_user": "admin",
  "admin_password": "(自動生成パスワード)",
  "front_page_id": 2,
  "finished_at": "2026-05-12T05:00:00Z"
}
```

### MCP を使わずに手元で完結させたい場合

`scripts/wp_runner.py` の `check_status` 部分はそのまま使えます。
インストール側を手元で動かすなら、同スクリプトを拡張して
お使いの XServer 操作手段(例:RPC、SDK、または `xserver-cli` 等)を
呼び出すように `install` の分岐を追加してください。

## ライセンス

社内利用を想定した未公開スクリプトです。再配布等は元オーナーに確認してください。

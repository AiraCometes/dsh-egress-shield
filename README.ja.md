# dsh-egress-shield

[English](README.md) | 日本語

[DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)（DSH）向けの、ローカルで動く **fail-closed** な秘匿化ゲートウェイです。DSH が LLM プロバイダーへ送るすべてのリクエストを、**手元のマシンで、送信の直前に**検査し、機密情報や個人情報を `[REDACTED_API_KEY_1]` のようなプレースホルダーに置き換えます。安全に検査・置換できないリクエストは送信しません。

> **ステータス: v0.1.0（初期版）**。`@deepseek-ai/dsh@0.2.0-rc.2` と、送信内容を記録するモックプロバイダーで検証しています（実際の LLM には一度も送信していません）。検出はルールベースなので完全ではありません。[保護できないもの](#保護できないもの)を必ず読んでください。

## なぜプラグインのフックではなくゲートウェイなのか

DSH の公開 API で書き換えられるのは、ユーザー入力とツール結果だけです。最終的なリクエストは書き換えられません。`llm/stream` フックではリクエストを差し替えられず、添付ファイルの絶対パスなど一部の内容は、そのフックより後で追加されます。そこで egress-shield は、**送信されるバイト列そのもの**を検査します。プロバイダーの `baseURL` を loopback のゲートウェイに向けるだけで、ゲートウェイはプラグインとして DSH のプロセス内で動きます。DSH 本体の変更も、常駐プロセスの追加も不要です。

```
DSH ── provider baseURL ──▶ http://127.0.0.1:47821/r/<route> ──▶ プロバイダー（opencode.ai、api.deepseek.com など）
        └── dsh-egress-shield プラグイン: ゲートウェイを同じプロセスで起動／未登録プロバイダーの拒否／直接送信の遮断
```

プロバイダーのアダプタを通るものはすべて対象です。会話、システムプロンプト、ツール結果、セッションタイトル、Compaction の要約、サブエージェント、リトライ、DeepSeek 公式 API の `dsh_session_log` フィールド（既定で除去）が含まれます。

## 検出対象

| カテゴリ | 例 | 扱い |
|---|---|---|
| `API_KEY` | [Gitleaks](https://github.com/gitleaks/gitleaks) から取り込んだ 221 ルール、`sk-…`、`ghp_…`、AWS、Slack、JWT、`Bearer …`、Cookie、URL クエリのトークン、`tskey-…` | 不可逆 |
| `SSH_KEY` | PEM / OpenSSH / PuTTY の秘密鍵（生のまま、`\n` エスケープ、途中で切れたもの）、SSH 公開鍵 | 不可逆 |
| `PASSWORD` | `password=…`、`--password …`、`scheme://user:pass@host`、`Password=…;` | 不可逆 |
| `CARD` | Luhn と発行会社の桁数で検証したカード番号 | 不可逆 |
| `TAILSCALE_URL` | `*.ts.net`（MagicDNS）、`100.64.0.0/10`、`fd7a:115c:a1e0::/48` | 仮名化 |
| `EMAIL`、`USERNAME`、`HOSTNAME` | メールアドレス、起動時に取得または通信から学習した OS のアカウント名・ホスト名 | 仮名化 |
| `PERSON`、`ADDRESS` | 日本語・英語の氏名（敬称、`氏名:`、`Dear …`、姓の辞書、ユーザー定義語）と住所 | 仮名化 |
| `PATH` | Linux、macOS、Windows、WSL（`/mnt/c/Users/…`、`\\wsl$\…`）、UNC、`file://` | 仮名化（接頭辞のみ） |

Base64、パーセントエンコード、`\uXXXX` エスケープの内側も、復号して検査します。同じ値は同じセッション内で常に同じプレースホルダーになります。不可逆カテゴリの元の値はどこにも保持しません（メモリにも残さず、鍵付きハッシュだけを持ちます）。

**パスの接頭辞だけを置換**: 識別につながる接頭辞だけを置き換えるので、モデルはプロジェクトの構造を理解したまま作業できます。たとえば `/home/alice/projects/app/src/index.ts` は `[REDACTED_PATH_1]/src/index.ts` になります。パス全体を置換したい場合は `pathMode: full` を指定してください。

**モデルへの通知**: 置換が発生したときは、検出したカテゴリだけを列挙した `[SECURITY REDACTION NOTICE]` をシステムプロンプトの末尾に追加します。会話の中に書かれた偽の通知やプレースホルダー風の文字列は中和します。

**ツール引数の復元**: モデルがローカルのファイル系ツールを `[REDACTED_PATH_1]/src/a.ts` で呼び出したら、ストリーミング中のツール呼び出しで実パスに戻します。復元するのは `PATH` と `USERNAME` だけで、対象はファイル系ツールと、ネットワークコマンドを含まないシェルだけです。Web、MCP、サブエージェントのツールには復元せず、秘密情報も復元しません。

**画像**: 画像の内容は検査できないので、送信前に DSH の承認 UI で確認を求めます。拒否された場合や応答がない場合は送信しません。

## 保護できないもの

- **ツールによる**外部通信（`web_fetch`、MCP サーバー、シェルの `curl` など）
- DSH の OpenTelemetry フィードバック送信（後述の `DSH_TELEMETRY_DISABLED=1` を推奨）
- ローカルに保存されるデータ（DSH のセッションログ、添付ファイル）
- 同じ DSH プロセス内で動く悪意あるプラグイン
- 承認した画像の内容
- 文脈の手がかりがなく、ユーザー定義語にも入っていない自由文中の人名。ルールベースの検出には漏れがあるので、重要な名前（本人、家族、取引先、社名、案件名）は[ユーザー定義語](#ユーザー定義語)に登録してください。

## 導入

必要なもの: Node.js 22 以上、DSH 0.2.x、`PATH` 上の pnpm（DSH の `dsh plugin add` が使います）。npm の名前はなりすましに使われやすいので、パッケージ名ではなく、レビューしたコミットから導入してください。

```sh
git clone https://github.com/AiraCometes/dsh-egress-shield ~/src/dsh-egress-shield
cd ~/src/dsh-egress-shield && git checkout <レビューしたコミット SHA>
dsh plugin --profile web add "link:$HOME/src/dsh-egress-shield"
```

ルートを設定するまでは、**すべての LLM リクエストが遮断されます**（fail-closed）。設定が終わるまでの間に漏洩することはありません。

### 設定

`~/.dsh/profiles/web/cordis.patch.yml` に追記します。

```yaml
- id: egress-shield
  config:
    listen: { host: 127.0.0.1, port: 47821 } # loopback のみ
    routes:
      opencode-go: { upstream: 'https://opencode.ai/zen/go/v1' }
      deepseek: { upstream: 'https://api.deepseek.com/anthropic' }
    routedProviders: [opencode-go] # 送信を許可する DSH のプロバイダー ID
    pathMode: anchored # anchored | full
    attachments: ask # ask | block | allow
    restore: { enabled: true }
    termsFile: ~/.config/egress-shield/terms.txt
    auditFile: ~/.local/state/egress-shield/audit.jsonl
```

次に、各プロバイダーの向き先をゲートウェイのルートに変えます。ほかの設定を上書きしないよう、**既存の**プロバイダー設定を編集してください（DSH の Settings → Models からでも変更できます）。

```yaml
- id: llm-pi-ai
  config:
    providers:
      opencode-go:
        baseURL: http://127.0.0.1:47821/r/opencode-go
```

DeepSeek 公式 API も使う場合は、`routedProviders` に `deepseek-official` を追加し、`llm-deepseek.baseURL` を `http://127.0.0.1:47821/r/deepseek` にします。ゲートウェイを経由せずに既知のプロバイダーのエンドポイントへ送ろうとしたリクエストは、DSH のプロセス内で遮断します。

| オプション | 既定値 | 意味 |
|---|---|---|
| `listen` | `127.0.0.1:47821` | ゲートウェイのアドレス。loopback 以外は起動を拒否 |
| `routes` | `{}` | `名前 → { upstream }`。`/r/<名前>` でアクセス |
| `routedProviders` | `[]` | 送信を許可する DSH のプロバイダー ID。それ以外は拒否 |
| `protectedEndpoints` | 主要プロバイダーの API | ゲートウェイ経由でしか到達させない URL の接頭辞 |
| `pathMode` | `anchored` | `anchored` は相対部分を残す、`full` はパス全体を置換 |
| `attachments` | `ask` | 画像・ファイルのアップロード: ユーザーに確認、`block`、`allow` |
| `restore` | 有効 | ツール引数の復元方針（`enabled`、`fileTools`、`shellTools`） |
| `stripFields` | `['dsh_session_log']` | 送信前に除去するトップレベルのフィールド |
| `termsFile` | `~/.config/egress-shield/terms.txt` | ユーザー定義語（パーミッションは `600` 必須） |
| `auditFile` | `~/.local/state/egress-shield/audit.jsonl` | 値を含まない監査ログ（件数とカテゴリのみ） |
| `anchors`、`usernames`、`hostnames` | `[]` | 追加で隠したいディレクトリ・アカウント・ホスト |

### ユーザー定義語

```sh
mkdir -p ~/.config/egress-shield && install -m 600 /dev/null ~/.config/egress-shield/terms.txt
```

```text
# 1 行に 1 語。「カテゴリ: 語」の形式、または語だけ（その場合は PERSON 扱い）
山田 太郎
ADDRESS: 千代田区千代田1-1
PERSON: 株式会社サンプル商事
```

このファイルが外部に送られることはありません。本人以外が読める権限になっている場合は読み込みません。

### 推奨する DSH の設定

- サービスの環境変数に `DSH_TELEMETRY_DISABLED=1`: フィードバックを送ったときに、DSH がセッションログの先頭部分を DeepSeek のテレメトリ収集サーバーへ送るのを止めます。これは LLM リクエストではないので、ゲートウェイでは秘匿化できません。
- `session-log-deepseek` を `enabled: false` にする（または Settings → General → *Upload Session Log…* を OFF）: DeepSeek API へのリクエストに生のセッションログが同梱されるのを止めます。ゲートウェイでも除去しますが、多重防御になります。

### 動作確認

```sh
curl -s http://127.0.0.1:47821/healthz   # 統計値のみで、値は返しません
echo 'key sk-proj-FAKEabcdef0123456789abcdef mail alice@example.com' | node bin/egress-shield.mjs scan
```

遮断されたリクエストは、DSH 上で `[egress-shield] Request blocked before leaving this machine: <CODE>` と表示されます。コード（`RESIDUAL_SECRET`、`ATTACHMENT_APPROVAL_REQUIRED`、`EGRESS_SHIELD_UNROUTED_PROVIDER` など）にデータが含まれることはありません。

### アンインストール

先にプロバイダーの `baseURL` を元に戻してから、`egress-shield` の設定を削除し、`dsh plugin --profile web remove dsh-egress-shield` を実行します（順番を逆にしても、送信が失敗するだけで漏洩はしません）。

### 他の Harness で使う

`node bin/egress-shield.mjs serve --config config.json` で、同じゲートウェイを単体で動かせます。単体モードでは `attachments` は `block` として扱われ、プロセス内の迂回防止ガードは使えません。

## 評価

架空のラベル付きコーパス（810 行）で、Gitleaks、TruffleHog（検証なし）、Presidio（spaCy）と比較しました。egress-shield は対象カテゴリの値をすべて検出し、陰性 300 件での誤検出は 0 件、処理時間は 49 ms、メモリは約 4 MB でした。ただし、コーパスはルールと一緒に作ったものなので、この数字は楽観的に見てください。文脈の手がかりがない自由文中の人名は 13% しか検出できませんでした（Presidio は 75% を検出しましたが、誤検出が 24%、メモリが 307 MB でした）。`just compare` で再測定できます。定常時のコストは、新規テキスト 1 MB あたり約 93 ms、4 MB の会話履歴の再送で約 11 ms です。

## 開発

Node 22 向けの JavaScript（ES Modules）で書いており、JSDoc の型を TypeScript（`checkJs`）で検査しています。ビルド工程も、ランタイム依存もありません。

| 用途 | ツール |
|---|---|
| ツールのバージョン管理 | [mise](https://mise.jdx.dev)（`mise.toml`） |
| タスクランナー | [just](https://just.systems)（`justfile`） |
| 整形・lint | Oxfmt・Oxlint |
| 型チェック | TypeScript 7（`tsc --noEmit`） |
| テスト | vitest（単体・結合・ReDoS・プラグイン、実際の DSH を使う E2E） |
| Git フック | [prek](https://prek.j178.dev)（`prek.toml`） |
| 秘密スキャン | Gitleaks |

```sh
just setup                    # mise install → npm ci → prek install
just check                    # 整形・lint・型・テスト・秘密スキャン
just test-e2e /path/to/@deepseek-ai/dsh/lib/bin.js
```

構成: `src/core`（Harness に依存しないエンジン）、`src/gateway`（loopback プロキシと wire 形式の処理）、`src/dsh`（DSH プラグイン）、`bin`（単体 CLI）、`test`（`test/support` にモックと架空コーパス）、`scripts`（ルールの取り込み、ベンチマーク、比較、読み取り専用のローカル DSH 監査）。

貢献については [CONTRIBUTING.md](CONTRIBUTING.md) を、脆弱性の報告方法は [SECURITY.md](SECURITY.md) を参照してください。

## 謝辞

- 秘密情報の検出ルールは [Gitleaks](https://github.com/gitleaks/gitleaks)（MIT）から取り込んでいます。[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) を参照してください。
- このプロジェクトは [Claude](https://claude.com)（Anthropic）の支援を受けて設計・実装しました。Claude と作成したコミットには `Co-Authored-By` トレーラーが付いています。

## ライセンス

[MIT](LICENSE) © 2026 AiraCometes

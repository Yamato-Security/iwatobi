<div align="center">
 <img src="art/logo.png" alt="Iwatobi Linux DFIR logo" width="640"/>
 <p>
  [<a href="README.md">English</a>] | [<b>日本語</b>]
 </p>
 <p>
   <b>Iwatobi（イワトビ）は、Linuxログ向けのSigmaベースの脅威ハンティングおよびファストフォレンジックのタイムライン作成ツールです。</b><br/>
   <a href="https://github.com/Yamato-Security">Yamato Security</a>が<a href="https://www.rust-lang.org/">Rust</a>で開発しました。
   Linuxのテキストログ版の<a href="https://github.com/Yamato-Security/hayabusa">Hayabusa</a>だと考えてください。
 </p>
 <p>
    <a href="https://github.com/Yamato-Security/iwatobi/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-AGPLv3-blue.svg?style=flat"/></a>
    <a href="https://twitter.com/SecurityYamato"><img src="https://img.shields.io/twitter/follow/SecurityYamato?style=social"/></a>
 </p>
</div>

---

## 🐧 概要

Iwatobiは、イワトビペンギンにちなんで名付けられた、メモリ安全なRustで書かれた**Linuxログ向けの脅威
ハンティングおよびファストフォレンジックのタイムライン作成ツール**です。Linuxサーバーに実際に存在する
テキストログ（syslog、`auth.log`、`cron`、Apacheとnginxのアクセスログとエラーログ、PHPとphp-fpmの
ログ）を読み込み、[Suzaku](https://github.com/Yamato-Security/suzaku)と同じ
[sigma-rust](https://github.com/Yamato-Security/sigma-rust)エンジンでネイティブな
[Sigma](https://github.com/SigmaHQ/sigma)ルールを適用し、必要なイベントだけを含むDFIRタイムラインを
作成します。

Iwatobiには、実行可能なSigmaHQのLinuxおよびWebサーバー向けルールに加えて、PHP2Shellの脆弱性
（CVE-2026-109618 / CVE-2026-109619）を検知する新しいルールセットが同梱されています。このルール
セットは、公開されているリモートコード実行が確認されたハニーポットの証拠データで検証済みです。

## ✨ 特徴

- **1つのコマンドで3種類の入力**: `dfir-timeline`は、単一のファイル（`-f`）、ディレクトリツリー
  （`-d`、`.1`や`.2.gz`などのローテーションされたファイルを含む）、または**ライブシステム**（`-l`）を
  スキャンします。ライブ解析では、読み込んだルールが必要とするログファイルを自動的に探し、ログソースが
  見つからない場合はディレクトリを入力するか、そのルールをスキップするかを尋ねます。syslogファイルが
  ないホストでは、`journalctl`経由でsystemdジャーナルを読み込みます。
- **ネイティブなSigma対応**: キーワードの正しいセマンティクス（キーワードは行内のどこにでも一致）、
  アクセスログに対するSigmaのWebサーバー用フィールド名（`c-ip`、`cs-method`、`cs-uri-query`、
  `sc-status`、`cs-user-agent`など）、そしてスライディングウィンドウで評価する**Sigma相関ルール**
  （`event_count`、`value_count`、`temporal`、`temporal_ordered`）に対応しています。
- **対応フォーマット**: RFC 3164 / RFC 5424 / rsyslogのISO形式のsyslogと`journalctl -o short-iso`の
  出力、vsftpdとClamAVのログ、Apache / nginxのアクセスログ（common、combined、vhost_combined、JSON
  Lines）、Apache 2.2/2.4とnginxのエラーログ、PHPのエラーログ、php-fpmのログ。PHPエンジンのメッセージは、
  どこに出力されていても認識します（Apacheのエラーログ、nginxのFastCGI stderr、php-fpm、syslog）。
- **カスタムフォーマット**: nginxの`log_format`やApacheの`LogFormat`を変更したアクセスログを自動的に
  認識します。それ以外のレイアウトも、`config/custom_log_formats.yaml`にnginxのフォーマット、Apacheの
  フォーマット、または正規表現で定義できます（[カスタムログフォーマット](#カスタムログフォーマットcustom-log-formats)）。
- **出力**: ターミナルにはカラーのタイムライン（タイムスタンプ、ルールタイトル、レベル、ログソース、
  ログファイル、行番号、詳細）を表示し、CSV / JSON / JSONLファイルにはDFIRレポートに必要な情報（MITRE ATT&CKの
  戦術と技術、解析したすべてのフィールド、ルールファイルとID、ログファイルと行番号）を保存します。
  プロファイルは`config/profiles.yaml`で設定できます。
- **タイムゾーン対応**: タイムゾーン情報を持たないログ（syslog、Apacheのエラーログ、php-fpm）は、
  `-z`で指定したタイムゾーン（デフォルトはローカル）として読み込みます。出力はローカル時刻またはUTC
  （`-U`）です。
- 結果サマリー、エラーログ、CSVの数式インジェクション対策、ターミナル出力の制御文字対策を備え、
  HayabusaやSuzakuと同じオプション文字を使用しています。

## ⬇️ ダウンロード

[Releases](https://github.com/Yamato-Security/iwatobi/releases)ページから、お使いのプラットフォーム
向けのパッケージをダウンロードしてください。各zipファイルには、バイナリ、`rules/`、`config/`、`art/`
フォルダ、ライセンス、英語版と日本語版のREADMEが含まれています。

| パッケージ | プラットフォーム |
| --- | --- |
| `iwatobi-<version>-lin-x64-gnu.zip` | Linux x64（glibc） |
| `iwatobi-<version>-lin-x64-musl.zip` | Linux x64、静的リンク（どのディストリビューションでも動作） |
| `iwatobi-<version>-lin-aarch64-gnu.zip` | Linux ARM64（glibc） |
| `iwatobi-<version>-lin-aarch64-musl.zip` | Linux ARM64、静的リンク |
| `iwatobi-<version>-mac-aarch64.zip` / `-mac-x64.zip` | macOS（Appleシリコン / Intel） |
| `iwatobi-<version>-win-x64.zip` / `-win-x86.zip` / `-win-aarch64.zip` | Windows |
| `iwatobi-<version>-all-platforms.zip` | 上記すべてのバイナリと1組のルール |

```bash
unzip iwatobi-0.1.0-lin-x64-musl.zip -d iwatobi
cd iwatobi
chmod +x iwatobi-0.1.0-lin-x64-musl
./iwatobi-0.1.0-lin-x64-musl help
```

`rules/`フォルダはバイナリと同じ場所に置いてください（または`-r`で指定します）。muslビルドは、古い
ディストリビューションや最小構成のディストリビューションでも動作するため、インシデントレスポンスに
最も使いやすい選択肢です。macOS版とWindows版では、Linuxマシンからコピーしたログをスキャンできます
（`-f`、`-d`）。ライブ解析（`-l`）はLinuxのみで利用できます。macOSでは、必要に応じて先にダウンロード
時の検疫属性を削除してください: `xattr -d com.apple.quarantine iwatobi-*`

## 🛠️ ソースからのビルド

```bash
git clone https://github.com/Yamato-Security/iwatobi.git
cd iwatobi
cargo build --release
./target/release/iwatobi -h
```

Rust 1.88以降が必要です。`config/`と`art/`のファイルはバイナリに埋め込まれています（バイナリと同じ
場所の`./config/`にコピーを置くと、そちらが優先されます）。`rules/`ディレクトリはバイナリと同じ場所に
置くか、`-r`で指定してください。

## 🚀 使い方

```bash
# 1つのファイル
iwatobi dfir-timeline -f /var/log/auth.log

# サーバーからコピーしたログのディレクトリ（タイムゾーンのないタイムスタンプはUTCで書かれたもの）
iwatobi dfir-timeline -d ./evidence/var/log -z UTC

# ローカルシステム（すべてのログを読むにはrootで実行）
sudo iwatobi dfir-timeline -l

# verboseプロファイルでCSVとJSONLを保存（UTC、時刻順にソート）
iwatobi dfir-timeline -d ./evidence/var/log -z UTC -U -s -o timeline -t csv,jsonl
```

### `dfir-timeline`のオプション

ヘルプの出力は英語のため、そのまま掲載しています。

```
Input:
  -d, --directory <DIR>     Directory of log files (scanned recursively; rotated and .gz files included)
  -f, --file <FILE>         File path to one log file
  -l, --live-analysis       Analyze the local log files that the loaded rules need (/var/log, journalctl)
      --log-format <FORMAT> Force the log format of every input file instead of detecting it: syslog,
                            applog, access, access-json, apache-error, nginx-error, php-error, php-fpm,
                            or the name of a custom format
      --custom-formats <FILE>  Custom log format definitions (default: config/custom_log_formats.yaml)

General Options:
  -r, --rules <DIR/FILE>    Specify a custom rule directory or file (default: ./rules)
  -z, --timezone <TZ>       Timezone of log timestamps that have no timezone information
                            (ex: UTC, Asia/Tokyo, +09:00) (default: local)
  -Q, --quiet-errors        Quiet errors mode: do not save error logs
  -w, --no-wizard           Do not ask questions (live analysis skips rules whose logs are not found)
      --threads <NUMBER>    Number of threads (default: optimal number for performance)

Filtering:
  -m, --min-level <LEVEL>   Minimum level for rules to load (default: informational)
  -D, --enable-deprecated-rules / -u, --enable-unsupported-rules
      --exclude-status / --include-status <STATUS...>
      --include-tag / --exclude-tag <TAG...>
      --timeline-start / --timeline-end <DATE>   RFC 3339 bounds for the events to load
      --time-offset <OFFSET>  Scan recent events based on an offset (ex: 1y, 3M, 30d, 24h, 30m)

Output:
  -o, --output <FILE>       Save the results to a file. The extension is set to the output type
                            (ex: -o timeline -t csv,jsonl writes timeline.csv and timeline.jsonl)
  -t, --output-type <FORMAT,...>  csv (default), json, jsonl
  -C, --clobber             Overwrite files when saving
  -p, --profile <PROFILE>   Output profile (default: standard on the terminal, verbose for files)
  -s, --sort                Sort events before output (warning: this uses much more memory!)
  -N, --no-summary          Do not display the results summary
  -U, --utc                 Output time in UTC format (default: local time)

Display Settings:
  -K, --no-color            Disable color output
  -q, --quiet               Quiet mode: do not display the launch banner
  -v, --verbose             Output verbose information (detected log formats, skipped files)
```

### ライブ解析

`-l`は、読み込んだすべてのルールのログソースを集め、`config/log_locations.yaml`
（`/var/log/syslog*`、`/var/log/auth.log*`、`/var/log/apache2/*`、`/var/log/nginx/*`、`/var/log/php*`
など）で探します。ホスト上にファイルがないログソースについては、ディレクトリを入力するか、そのログ
ソースを必要とするルールをスキップするかを尋ねます。`-w, --no-wizard`を指定すると尋ねずにスキップ
します。Iwatobiがターミナルに接続されていない場合も同じ動作になります。journaldしかないホストでは、
`journalctl -o short-iso-precise`でジャーナルをエクスポートし、syslogとしてスキャンします。すべての
ログを読むには、ライブ解析をroot（または`adm` / `systemd-journal`グループのメンバー）で実行して
ください。

### タイムスタンプ

syslog（RFC 3164）、Apacheのエラーログ、nginxのエラーログ、php-fpmの行にはタイムゾーン情報が
ありません。Iwatobiはこれらを`-z`で指定したタイムゾーン（デフォルトはIwatobiを実行しているマシンの
ローカルタイムゾーン）として読み込みます。アクセスログ、ISO形式のsyslog行、タイムゾーントークンを
持つPHPのエラーログ行（`[24-Oct-2026 15:35:33 UTC]`）は自身のタイムゾーンを持つため、書かれている
とおりに使用します。タイムゾーントークンのないPHPの行も`-z`で読み込みます。出力はデフォルトでローカル
時刻、`-U`でUTCです。RFC 3164の行には年もないため、ファイルの更新日時の年を使用し、それでは未来の
日時になる行は1年前とみなします。

### カスタムログフォーマット（Custom log formats）

Iwatobiは各ファイルのフォーマットを自動的に判別します。[特徴](#-特徴)に挙げた組み込みのフォーマットに
加えて、レイアウトが変更されたログも扱えます。

**レイアウトが異なるアクセスログは自動的に認識します。** nginxの`log_format`やApacheの`LogFormat`は
よく変更されます（バーチャルホストを先頭に置く、リクエストをメソッド・URL・プロトコルに分ける、
応答時間を追加する、など）。ファイルがどの組み込みフォーマットにも一致しない場合、Iwatobiは先頭の行を
読んで各列の内容を判別します。判別するのは、時刻（`[24/Oct/2026:15:35:32 +0000]`、ISO 8601、エポック秒）、
リクエスト（引用符で囲まれたリクエスト行、またはメソッド・URL・プロトコル）、ステータス、クライアントIP、
リファラー、ユーザーエージェント、送信バイト数、バーチャルホストです。少なくとも時刻・リクエスト・
ステータス・クライアントIP・ユーザーエージェントがあり、サンプルのほぼすべての行が当てはまる場合にだけ
そのレイアウトを使います。各列には組み込みのアクセスログと同じSigmaのWebサーバーのフィールド名
（`c-ip`、`cs-method`、`cs-uri-query`、`sc-status`など）が付くので、`webserver`のルールがすべて
適用されます。その他の列は`Details`に`field<N>`（Nは列番号）として残ります。

スキャンの後、検出したレイアウトをnginxの`log_format`として表示します。

```
Access log layout detected automatically: 12 files
    [$time_local] $remote_addr $host $request_method $request_uri $server_protocol $status $body_bytes_sent $field9 "$http_referer" "$http_user_agent"
```

一度確認してください。列の判別が間違っている場合や、`field<N>`の列に名前を付けたい場合は、この
レイアウトをnginxのフォーマットとして`config/custom_log_formats.yaml`にコピーして修正します
（`$field9` → `$request_time`）。

**その他のレイアウトは`config/custom_log_formats.yaml`に定義します。** どのフォーマットにも一致しない
ファイルはスキップされ、スキャンの最後に`3 files were skipped because the log format was not recognized`
のような警告が表示されます（`-v`で一覧を表示します）。各エントリには`name`と、次のいずれか1つを書きます。

| キー | 値 |
| --- | --- |
| `nginx` | nginxの`log_format`の文字列、または`nginx.conf`の`log_format`ディレクティブ全体 |
| `apache` | Apacheの`LogFormat`の文字列、または`LogFormat`ディレクティブ全体 |
| `regex` | フィールドごとに名前付きグループを持つ正規表現: `(?P<name>...)` |

任意の設定:

| キー | 値 |
| --- | --- |
| `files` | そのフォーマットを使うファイル名のパターン（`*`、`?`、`[abc]`）。`/`を含むパターンはパス全体と照合します。`files`がない場合はすべてのファイルで試し、先頭の行の半分以上に一致したときに使います |
| `time_format` | 時刻のフォーマット（[chronoのstrftime](https://docs.rs/chrono/latest/chrono/format/strftime/index.html)の書式。例: `'%Y-%m-%d %H:%M:%S'`）。省略するとCLF、ISO 8601、エポック秒を読み取ります。タイムゾーンのない時刻は`-z`で指定したタイムゾーンとして読み込みます |
| `logsource` | （`regex`のみ）ログのSigmaのlogsource。デフォルトは`{category: webserver}`。例: `{product: linux, service: auth}`、`{product: apache, service: error}` |

```yaml
formats:
  # nginx.confからコピー
  - name: shop-nginx
    nginx: |
      log_format shop '$remote_addr [$time_local] "$request" '
                      '$status $body_bytes_sent $request_time';
    files: ['shop-access.log*']

  # Apache: タイムゾーンのない日付と時刻（-zで読み込み）
  - name: intranet-apache
    apache: '%{%Y-%m-%d %H:%M:%S}t %h "%r" %>s %b "%{User-Agent}i" %D'
    files: ['intranet*.log']

  # Webサーバー以外のログ: 正規表現とlogsource
  - name: vpnd
    regex: '^(?P<timestamp>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) (?P<hostname>\S+) (?P<process>[\w-]+)\[(?P<pid>\d+)\]: (?P<message>.*)$'
    time_format: '%Y-%m-%d %H:%M:%S'
    logsource: {product: linux, service: sshd}
    files: ['vpnd*.log']
```

Webサーバーのフォーマット（`nginx`、`apache`、logsourceが`webserver`の`regex`）では、次の名前を
Sigmaのフィールドに対応付けます。その他の変数やグループは、その名前のまま`Details`に入ります。

| nginxの変数 / 正規表現のグループ | Apache | Sigmaのフィールド |
| --- | --- | --- |
| `remote_addr`、`client_ip` | `%h`、`%a` | `c-ip` |
| `request`（`GET /x HTTP/1.1`） | `%r` | `cs-method`、`cs-uri-query`、`cs-version` |
| `request_method` | `%m` | `cs-method` |
| `request_uri`（または`uri` + `args`） | `%U%q` | `cs-uri-query`、`cs-uri-stem` |
| `server_protocol` | `%H` | `cs-version` |
| `status` | `%s`、`%>s` | `sc-status` |
| `body_bytes_sent`、`bytes_sent` | `%b`、`%B`、`%O` | `sc-bytes` |
| `http_referer` | `%{Referer}i` | `cs-referer` |
| `http_user_agent` | `%{User-Agent}i` | `cs-user-agent` |
| `host`、`http_host`、`server_name` | `%v`、`%V` | `cs-host` |
| `remote_user` | `%u` | `cs-username` |
| `time_local`、`time_iso8601`、`msec`、`time`、`timestamp` | `%t`、`%{format}t` | イベントの時刻 |

`regex`では、Sigmaのフィールド名の`-`を`_`に置き換えて書きます（`c_ip`、`cs_method`、`sc_status`）。
グループ名には`-`を使えないためです。カスタムフォーマットの名前は`--log-format`にも指定でき
（`--log-format shop-nginx`）、`-v`では`custom:shop-nginx`のように表示されます（自動検出したレイアウトは
`access-auto`）。別のファイルから定義を読み込むには`--custom-formats <FILE>`を使います。

### 出力プロファイル

| プロファイル | 列 |
| --- | --- |
| `minimal` | Timestamp, RuleTitle, Level, Details |
| `standard`（ターミナルのデフォルト） | Timestamp, RuleTitle, Level, LogSource, LogFile, LineNumber, Details |
| `verbose`（ファイル出力のデフォルト） | standard + MitreTactics, MitreTags, OtherTags, RuleFile, RuleID |
| `super-verbose` | verbose + RawLine, RuleAuthor, RuleCreationDate, RuleModifiedDate, Status, Description, References, FalsePositives |

`Details`には、解析したイベントのすべてのフィールドが主要なものから順に入ります（syslogでは`Proc`、
`PID`、`Msg`、アクセスログでは`SrcIP`、`Method`、`URI`、`Status`、`Bytes`、`Referer`、`UA`など）。
CSVとターミナルでは`Key: value ¦ Key: value`の形式で表示し、JSON/JSONLではオブジェクトとして出力します。
正確な列は`iwatobi list-profiles`で確認できます。Hayabusaのような`Computer`列はありません。syslogの
ホスト名を表示したい場合は、プロファイルに`%Computer%`を追加してください。

`LogFile`と`LineNumber`は、イベントが記録された場所を示します。相関ルールのアラートでは、`LogFile`に
元になったイベントのログファイルを列挙し、`LineNumber`は`-`になります。PHP自身がメッセージ内で報告する
スクリプトの場所（`... in /var/www/html/index.php on line 12`）はログの場所ではないため、
`Details`に`PhpFile` / `PhpLine`として表示します。

## 📏 ルール

ルールは[`rules/`](rules/README.md)にあります。`rules/sigma/`には、Iwatobiが実行するアップストリーム
のルールをSigmaHQリポジトリと同じディレクトリ構成で置いています。`rules/iwatobi/`には、Iwatobi用に
作成したルールを置いています。ルールは、その`logsource`がIwatobiの生成できるものである場合に読み込まれ
ます。

| Sigmaの`logsource` | ログ |
| --- | --- |
| `product: linux` + `service: syslog` / `auth` / `sshd` / `cron` / `sudo` / `vsftpd` / `clamav` / `guacamole` | syslog系のファイル、`journalctl`の出力、vsftpd / ClamAVのログ |
| `category: webserver` | Apache / nginxのアクセスログ |
| `service: apache`（または`product: apache, service: error`） | Apacheのエラーログ |
| `service: nginx`（または`product: nginx, service: error`） | nginxのエラーログ |
| `product: php, service: error_log` | PHPのエラーログ、および他のログ内のPHPメッセージ |
| `product: php, service: fpm` | php-fpmのログ |

auditd、Sysmon for Linux、Webプロキシ向けのルールにはまだ対応していないため、起動時にスキップされます
（スキップした数が表示されます）。

### PHP2Shell（CVE-2026-109618 / CVE-2026-109619）

`rules/iwatobi/php/php2shell/`、`rules/iwatobi/web/`、`rules/iwatobi/php/fpm/`のルールは、PHP2Shellの
攻撃チェーンが通常のログに残す痕跡から攻撃を検知します。これらのルールは、
[0x4D31/honeypot-data](https://github.com/0x4D31/honeypot-data/tree/main/reports/php2shell)で公開
されている35件のRCE事例で検証済みです。

| ルール | ログ | レベル |
| --- | --- | --- |
| PHP Memory Exhausted Before Script Execution | PHPのエラーログ（`in Unknown on line 0`） | high |
| PHP Session ID Too Long Or Illegal Characters | PHPのエラーログ | high |
| PHP Outbound HTTP Request From Command Line Code | PHPのエラーログ（`php -r`によるコールバック） | medium |
| PHP POST Content-Length Exceeds Limit | PHPのエラーログ | low |
| Apache Worker Process Exited On Abort Or Bus Error Signal | Apacheのエラーログ（SigmaHQのセグメンテーション違反ルールと併用） | high |
| Shell Error Output In Apache Error Log | Apacheのエラーログ（`sh: 1: wget: not found`） | high |
| PHP-FPM Child Process Exited On Signal / PHP-FPM Child Shell Error Output | php-fpmのログ | high |
| PHP2Shell PoC Memory Pressure Request | アクセスログ（`q0000000=v&q0000001=v...`） | high |
| Rapid Repeated POST Requests To PHP Index Page | アクセスログ、相関ルール（クライアントごとに60秒間に3回のPOST） | medium |
| PHP2Shell Exploitation Chain | メモリ枯渇 + セッションID + ワーカークラッシュの5分以内の相関 | critical |

`test_files/php2shell/`のテストデータは、この証拠データから作成したものです（CC BY 4.0）。
`iwatobi dfir-timeline -d test_files/php2shell -z UTC`でスキャンできます（Apacheのエラーログには
タイムゾーンがなく、PHPのログはUTCです）。

#### 元のPHP2Shellハニーポットの証拠データで試す

ハニーポットのログは、[0x4D31/honeypot-data](https://github.com/0x4D31/honeypot-data)でCC BY 4.0の
ライセンスで公開されています。次のいずれかの方法で取得してください（リポジトリ全体で約11MBです）。

```bash
# 1. リポジトリ全体をシャロークローン
git clone --depth 1 https://github.com/0x4D31/honeypot-data.git

# 2. または、PHP2Shellのレポートだけを取得（スパースチェックアウト）
git clone --depth 1 --filter=blob:none --sparse https://github.com/0x4D31/honeypot-data.git
git -C honeypot-data sparse-checkout set reports/php2shell

# 3. または、gitを使わずにリポジトリのアーカイブをダウンロードして展開
curl -L -o honeypot-data.zip https://github.com/0x4D31/honeypot-data/archive/refs/heads/main.zip
unzip -q honeypot-data.zip && mv honeypot-data-main honeypot-data
```

RCEが確認された証拠データは`honeypot-data/reports/php2shell/2026-10-24-rce-evidence/`にあります。
事例ごとにフォルダ（`episode-a/A01` ... `episode-b/B32`）があり、それぞれにApacheのJSON形式のアクセス
ログ（`web.jsonl`）、PHPのエラーログ、Apacheのエラーログ、Apacheの子プロセスのstderrが含まれています。
Apacheのエラーログにはタイムゾーンがなく、PHPのエラーログはUTCのため、ツリー全体を`-z UTC`で
スキャンしてください。

```bash
EVIDENCE=honeypot-data/reports/php2shell/2026-10-24-rce-evidence

# ターミナルにタイムラインを表示（UTC）
./iwatobi dfir-timeline -d "$EVIDENCE" -z UTC -U

# highとcriticalのアラートのみ、サマリーなし
./iwatobi dfir-timeline -d "$EVIDENCE" -z UTC -U -m high -N

# verboseプロファイル（ルール、MITREタグ、ログファイルと行番号）で、ソートしたCSVとJSONLを保存
./iwatobi dfir-timeline -d "$EVIDENCE" -z UTC -U -s -o php2shell-timeline -t csv,jsonl

# 1つの事例のみ
./iwatobi dfir-timeline -d "$EVIDENCE/episode-a/A01" -z UTC -U
```

（`./iwatobi`はパッケージ内のバイナリを指します。例: `./iwatobi-0.1.0-lin-x64-musl`）パケット
キャプチャ（`traffic.pcap.gz`）、Tetragonのプロセスイベント、事例のメタデータは、Iwatobiが解析する
テキストログではないため、スキップされてエラーログに記録されます（`-v`で表示されます）。Iwatobi 0.1.0
の検証で284個のファイルをスキャンした結果は次のとおりです。

| ルール | 検知数 |
| --- | ---: |
| PHP Memory Exhausted Before Script Execution | 139 |
| Apache Segmentation Fault | 83 |
| PHP2Shell PoC Memory Pressure Request | 52 |
| PHP Session ID Too Long Or Illegal Characters | 51 |
| Shell Error Output In Apache Error Log | 29 |
| Rapid Repeated POST Requests To PHP Index Page（相関ルール） | 27 |
| PHP2Shell Exploitation Chain（相関ルール） | 12 |
| PHP Outbound HTTP Request From Command Line Code | 9 |
| Apache Worker Process Exited On Abort Or Bus Error Signal | 7 |

RCEが確認された35件の事例はすべて検知されます。公開されている事例のフォルダは時間的に重なっており、
一部のログ行が重複しているため、`test_files/php2shell/`よりも検知数が多くなります。

## 🧪 開発

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

`tests/cli.rs`の統合テストは、`test_files/`に対してバイナリを実行し、テストデータの各行から手作業で
導き出した検知数を確認します。

## 🤝 コントリビューションとライセンス

バグ報告、解析できないログのサンプル、新しいルールは、IssueやPull Requestで歓迎しています。
IwatobiはAGPLv3（[LICENSE](LICENSE)）のもとで公開されており、著作権はYamato Securityに帰属します。

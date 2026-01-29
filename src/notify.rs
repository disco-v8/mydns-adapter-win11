//! IPアドレスの更新通知をMyDNS.JPサーバーに送信するロジックを管理するモジュール。
//!
//! このモジュールは、以下の機能を提供します。
//! - コマンドラインからの即時通知 (`--notify`, `--ipv4`, `--ipv6`) の実行
//! - Windowsサービスからの定期的な通知実行
//! - 指定されたURLへのHTTP Basic認証を用いた通知リクエストの送信
//!
//! 通知処理は、`reqwest`クレートを利用して同期的（ブロッキング）に実行されます。

use crate::i18n::get_msg_en;
use crate::logging::{log_error, log_info};
use crate::registry::{Config, load_all_configs};
use reqwest::blocking::Client;
use std::io;

/// 「即時通知モード」を処理します。
///
/// この関数は `--notify`, `--ipv4`, `--ipv6` いずれかのフラグが指定されたときに呼び出されます。
/// すべての設定を読み込み、各アカウントに対して一度だけ通知処理を実行します。
/// 通知を行うかどうかは、コマンドラインフラグと各アカウントの設定の両方が有効である必要があります。
///
/// # 引数
/// * `use_ipv4` - `--notify` または `--ipv4` が指定された場合に `true`。
/// * `use_ipv6` - `--notify` または `--ipv6` が指定された場合に `true`。
pub fn notify_now_mode(use_ipv4: bool, use_ipv6: bool) -> io::Result<()> {
    log_info(get_msg_en("log_notify_start"));
    let configs = load_all_configs().unwrap_or_else(|_| Vec::new());
    if configs.is_empty() {
        // 設定されているアカウントがなければ、何もせずに終了します。
        log_error(get_msg_en("log_config_missing"));
        return Ok(());
    }

    let client = Client::new();
    for config in configs {
        // Consider settings file values as well
        // この通知実行のための一時的な設定を作成します。
        // 通知が実行されるのは、コマンドラインフラグが有効で、かつ
        // アカウント自体の設定も有効になっている場合のみです。
        let mut temp_config = config.clone();
        temp_config.ipv4_notify = use_ipv4 && config.ipv4_notify;
        temp_config.ipv6_notify = use_ipv6 && config.ipv6_notify;

        perform_notification(&client, &temp_config);
    }

    log_info(get_msg_en("log_notify_finish"));
    Ok(())
}

/// ひとつのアカウント設定に基づいて、IPアドレスの通知を実行します。
///
/// この関数は「即時通知モード」とWindowsサービスの定期実行ループの両方から呼び出されます。
/// 引数で渡された`Config`構造体の`ipv4_notify`と`ipv6_notify`フラグをチェックし、
/// 有効になっているプロトコルの通知処理をそれぞれ呼び出します。
pub fn perform_notification(client: &Client, config: &Config) {
    if config.ipv4_notify {
        // IPv4通知が有効な場合
        if let Err(e) = notify(
            client,
            "https://ipv4.mydns.jp/login.html",
            &config.master_id,
            &config.password,
        ) {
            let msg = get_msg_en("log_ipv4_fail_fmt").replace("{}", &e.to_string());
            // エラーが発生した場合はログに記録します。
            log_error(&format!("[{}] {}", config.master_id, msg));
        }
    }
    if config.ipv6_notify {
        // IPv6通知が有効な場合
        if let Err(e) = notify(
            client,
            "https://ipv6.mydns.jp/login.html",
            &config.master_id,
            &config.password,
        ) {
            let msg = get_msg_en("log_ipv6_fail_fmt").replace("{}", &e.to_string());
            // エラーが発生した場合はログに記録します。
            log_error(&format!("[{}] {}", config.master_id, msg));
        }
    }
}

/// MyDNS.JPのエンドポイントに単一の通知リクエストを送信します。
///
/// 指定されたURLに対して、Basic認証を用いてGETリクエストを送信します。
/// リクエストの成功・失敗の結果をログに記録します。
///
/// # 引数
/// * `client` - リクエストに使用する`reqwest::blocking::Client`インスタンス。
/// * `url` - MyDNS.JPの通知用URL（IPv4またはIPv6用）。
/// * `id` - 認証に使用するMasterID。
/// * `pw` - 認証に使用するパスワード。
///
/// # 戻り値
/// HTTPリクエストの成否を示す`reqwest::Result`。
fn notify(client: &Client, url: &str, id: &str, pw: &str) -> reqwest::Result<()> {
    // Basic認証情報を付与してGETリクエストを送信します。
    let res = client.get(url).basic_auth(id, Some(pw)).send()?;
    let status = res.status();
    // HTTPステータスコードが2xx台（成功）かどうかをチェックします。
    if status.is_success() {
        let msg = get_msg_en("log_notify_status_fmt")
            .replacen("{}", url, 1)
            .replacen("{}", &status.to_string(), 1);
        log_info(&format!("[{}] {}", id, msg));
        Ok(())
    } else {
        // ステータスが成功でない場合（401認証エラー、500サーバーエラーなど）、
        // `error_for_status()`はレスポンスを`Err`に変換します。
        // `is_success()`が`false`なので、`unwrap_err()`は常に安全です。
        Err(res.error_for_status().unwrap_err())
    }
}

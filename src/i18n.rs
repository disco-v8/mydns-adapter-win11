//! 国際化（i18n）メッセージを管理するモジュール。
//!
//! ユーザーのUI言語設定（日本語かそれ以外か）に応じて、
//! 対応するメッセージ文字列を返します。
//! サービスログなど、ロケールに依存すべきでない場面では、
//! 英語メッセージを直接取得する関数も提供します。

use windows::Win32::Globalization::GetUserDefaultUILanguage;

/// ユーザーのUI言語設定に応じて、ローカライズされたメッセージを取得します。
#[rustfmt::skip]
#[allow(clippy::if_same_then_else)]
pub fn get_msg(key: &str) -> &str {
    // GetUserDefaultUILanguage() はユーザーのデフォルトUI言語のIDを返します。
    // 1041 (0x0411) は日本語の言語IDです。
    let is_jp = unsafe { GetUserDefaultUILanguage() == 1041 };
    get_msg_lang(key, is_jp)
}

/// 常に英語のメッセージを取得します。
///
/// サービスログなど、表示環境の言語設定に依存すべきでない場合に使用します。
#[rustfmt::skip]
#[allow(clippy::if_same_then_else)]
pub fn get_msg_en(key: &str) -> &str {
    get_msg_lang(key, false)
}

/// メッセージキーとロケール（日本語か否か）に基づいて、具体的なメッセージ文字列を返します。
///
/// この関数は、アプリケーション内で使用されるすべての静的文字列を集中管理します。
/// `#[rustfmt::skip]` と `#[allow(clippy::if_same_then_else)]` は、
/// この巨大なmatch文の可読性を保つために意図的に使用されています。
#[rustfmt::skip]
#[allow(clippy::if_same_then_else)]
fn get_msg_lang(key: &str, is_jp: bool) -> &str {
    match key {
        // main.rs
        "config_title" => if is_jp { "--- MyDNS Adapter 設定 ---" } else { "--- MyDNS Adapter Configuration ---" },
        "config_loaded" => if is_jp { "\n現在の設定を読み込みました。変更しない項目はEnterキーを押してください。" } else { "\nCurrent configuration loaded. Press Enter to keep current values." },
        "master_id_prompt" => if is_jp { "MasterID" } else { "MasterID" },
        "password_prompt" => if is_jp { "パスワード" } else { "Password" },
        "ipv4_notify_prompt" => if is_jp { "IPv4通知を有効にしますか？" } else { "Enable IPv4 notification?" },
        "ipv6_notify_prompt" => if is_jp { "IPv6通知を有効にしますか？" } else { "Enable IPv6 notification?" },
        "registry_save_success" => if is_jp { "\n[成功] 設定をレジストリに保存しました。" } else { "\n[Success] Configuration saved to registry." },
        "registry_save_fail_fmt" => if is_jp { "\n[失敗] レジストリ保存エラー: {}" } else { "\n[Failed] Registry save error: {}" },
        "input_prompt_pw_fmt" => if is_jp { "{}を入力してください (現在値: {}, 変更しない場合はEnter): " } else { "Enter {} (Current: {}, Enter to keep): " },
        "input_prompt_fmt" => if is_jp { "{}を入力してください (現在値: {}): " } else { "Enter {} (Current: {}): " },
        "input_prompt_new_fmt" => if is_jp { "{}を入力してください: " } else { "Enter {}: " },
        "not_set" => if is_jp { "(未設定)" } else { "(Not set)" },
        "yes_no_prompt_fmt" => if is_jp { "{} (現在値: {}) {}: " } else { "{} (Current: {}) {}: " },
        "yes_no_hint_true" => if is_jp { "(Y/n)" } else { "(Y/n)" },
        "yes_no_hint_false" => if is_jp { "(y/N)" } else { "(y/N)" },
        "yes_no_invalid" => if is_jp { "'y' または 'n' を入力するか、Enterキーを押してください。" } else { "Please enter 'y' or 'n', or press Enter." },
        "view_title" => if is_jp { "--- 現在のMyDNS Adapter設定 ---" } else { "--- Current MyDNS Settings ---" },
        "view_master_id_fmt" => if is_jp { "MasterID: {}" } else { "MasterID: {}" },
        "view_password_fmt" => if is_jp { "パスワード: {}" } else { "Password: {}" },
        "view_ipv4_fmt" => if is_jp { "IPv4 Notify: {}" } else { "IPv4 Notify: {}" },
        "view_ipv6_fmt" => if is_jp { "IPv6 Notify: {}" } else { "IPv6 Notify: {}" },
        "yes" => if is_jp { "Yes" } else { "Yes" },
        "no" => if is_jp { "No" } else { "No" },
        "view_no_accounts" => if is_jp { "アカウントが設定されていません。" } else { "No accounts are configured." },
        "view_list_fmt" => if is_jp { "MasterID: {id},  パスワード: {pw},  IPv4 Notify: {v4},  IPv6 Notify: {v6}" } else { "MasterID: {id},  Password: {pw},  IPv4 Notify: {v4},  IPv6 Notify: {v6}" },
        "add_title" => if is_jp { "--- 新規アカウント追加 ---" } else { "--- Add New Account ---" },
        "edit_title" => if is_jp { "--- アカウント編集 ---" } else { "--- Edit Account ---" },
        "remove_title" => if is_jp { "--- アカウント削除 ---" } else { "--- Remove Account ---" },
        "account_exists_fmt" => if is_jp { "アカウント '{}' は既に存在します。" } else { "Account '{}' already exists." },
        "account_not_found_fmt" => if is_jp { "アカウント '{}' は見つかりませんでした。" } else { "Account '{}' not found." },
        "select_account_prompt" => if is_jp { "編集するアカウントを選択してください:" } else { "Select an account to edit:" },
        "select_account_index_prompt" => if is_jp { "番号またはMasterIDを入力してください: " } else { "Enter number or MasterID: " },
        "invalid_selection" => if is_jp { "無効な選択です。" } else { "Invalid selection." },
        "confirm_remove_fmt" => if is_jp { "本当にアカウント '{}' を削除しますか？" } else { "Are you sure you want to remove account '{}'?" },
        "confirm_prompt_fmt" => if is_jp { "{} {}: " } else { "{} {}: " },
        "remove_success" => if is_jp { "[成功] アカウントを削除しました。" } else { "[Success] Account removed successfully." },
        "remove_fail_fmt" => if is_jp { "[失敗] アカウント削除エラー: {}" } else { "[Failed] Failed to remove account: {}" },
        "add_success" => if is_jp { "[成功] アカウントを追加しました。" } else { "[Success] Account added successfully." },
        "no_accounts_add_prompt" => if is_jp { "アカウントが見つかりません。新規作成しますか？" } else { "No accounts found. Create new?" },
        "operation_cancelled" => if is_jp { "操作をキャンセルしました。" } else { "Operation cancelled." },
        "edit_target_fmt" => if is_jp { "対象アカウント: {}" } else { "Target Account: {}" },
        "invalid_master_id_prefix" => if is_jp { "MasterIDは 'mydns' で始まる必要があります。" } else { "MasterID must start with 'mydns'." },

        // winservice.rs
        "admin_required_install" => if is_jp { "サービスのインストールには管理者権限が必要です。管理者として実行してください。" } else { "Administrator privileges are required to install the service. Please run as administrator." },
        "service_installing_fmt" => if is_jp { "サービス '{}' をインストールしています..." } else { "Service '{}' installing..." },
        "service_installed_fmt" => if is_jp { "サービス '{}' が正常にインストールされ、開始されました。" } else { "Service '{}' installed and started successfully." },
        "admin_required_uninstall" => if is_jp { "サービスのアンインストールには管理者権限が必要です。管理者として実行してください。" } else { "Administrator privileges are required to uninstall the service. Please run as administrator." },
        "service_not_installed_fmt" => if is_jp { "サービス '{}' はインストールされていません。" } else { "Service '{}' is not installed." },
        "service_stopping_fmt" => if is_jp { "サービス '{}' を停止しています..." } else { "Stopping service '{}'..." },
        "service_stopped" => if is_jp { "サービスが停止しました。" } else { "Service stopped." },
        "service_waiting_stop" => if is_jp { "サービスの停止を待機しています..." } else { "Waiting for service to stop..." },
        "service_not_running" => if is_jp { "サービスが起動していません。" } else { "Service is not running." },
        "service_uninstalled_fmt" => if is_jp { "サービス '{}' が正常にアンインストールされました。" } else { "Service '{}' uninstalled successfully." },
        "log_service_failed_fmt" => if is_jp { "サービスの実行に失敗しました: {}" } else { "Service failed to run: {}" },
        "log_service_started" => if is_jp { "サービスを開始しました。" } else { "Service started." },
        "log_service_config_missing" => if is_jp { "MasterIDまたはパスワードが設定されていません。サービスを停止します。" } else { "MasterID or Password is not set. Service will stop." },
        "log_service_stopping" => if is_jp { "サービスを停止します。" } else { "Service stopping." },
        "admin_required_restart" => if is_jp { "サービスの再起動には管理者権限が必要です。管理者として実行してください。" } else { "Administrator privileges are required to restart the service. Please run as administrator." },
        "service_restarted_successfully" => if is_jp { "サービスを再起動しました。" } else { "Service restarted successfully." },

        // notify.rs
        "log_notify_start" => if is_jp { "即時通知を開始します。" } else { "Starting immediate notification." },
        "log_config_missing" => if is_jp { "MasterIDまたはパスワードが設定されていません。先に設定モードを実行してください。" } else { "MasterID or Password is not set. Please run configuration mode first." },
        "log_notify_finish" => if is_jp { "即時通知が完了しました。" } else { "Immediate notification finished." },
        "log_ipv4_fail_fmt" => if is_jp { "IPv4通知に失敗しました: {}" } else { "IPv4 Notification failed: {}" },
        "log_ipv6_fail_fmt" => if is_jp { "IPv6通知に失敗しました: {}" } else { "IPv6 Notification failed: {}" },
        "log_notify_status_fmt" => if is_jp { "通知完了 {}: ステータス {}" } else { "Notified {}: Status {}" },

        _ => key,
    }
}

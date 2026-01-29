//! アプリケーションのメインエントリーポイントとコマンドラインインターフェース（CLI）を定義するモジュール。
//!
//! このモジュールは以下の役割を担います。
//! - `clap`クレートを用いて、`--add`, `--edit`, `--install` などのコマンドライン引数を解析します。
//! - 解析された引数に基づき、`winservice`、`registry`、`notify` などの各モジュールに対応する処理をディスパッチします。
//! - アカウントの追加や編集など、ユーザーとの対話的な設定処理を実装します。
//! - Windowsサービスとして実行するための特別なエントリーポイント (`--service` フラグの処理) を提供します。

use std::env;
use std::io::{self, Write};

use clap::Parser;
use rpassword::read_password;

// --- アプリケーションの各機能を実装したモジュール群 ---
mod i18n;
mod logging;
mod notify;
mod registry;
mod winservice;

// --- 各モジュールから必要な関数や構造体をインポート ---
use i18n::get_msg;
use logging::{log_error, log_info};
use notify::notify_now_mode;
use registry::{delete_config, load_all_configs, save_to_registry};
use winservice::{install_service, restart_service, run_service, uninstall_service};

/// clapクレートを利用してコマンドライン引数を定義する構造体。
/// 各フィールドが、アプリケーションが受け付けるコマンドラインオプションに対応します。
#[derive(Parser, Debug)]
#[command(author, version, about = "MyDNS.JP Adapter for Windows", long_about = None)]
struct Args {
    /// 新しいアカウント設定を追加します。
    #[arg(short, long)]
    add: bool,

    /// 既存のアカウント設定を編集します。MasterIDを省略した場合は、対話的に選択します。
    #[arg(short, long, num_args(0..=1), default_missing_value = "_INTERACTIVE_")]
    edit: Option<String>,

    /// 指定されたMasterIDのアカウント設定を削除します。
    #[arg(short, long)]
    remove: Option<String>,

    /// 現在の設定を一覧表示します。
    #[arg(short, long)]
    view: bool,

    /// 現在の設定を1行で簡潔に一覧表示します。（--viewのエイリアス）
    #[arg(short, long)]
    list: bool,

    /// IPv4とIPv6の両方のアドレスを即時通知します。
    #[arg(short, long)]
    notify: bool,

    /// IPv4アドレスを即時通知します。
    #[arg(short = '4', long)]
    ipv4: bool,

    /// IPv6アドレスを即時通知します。
    #[arg(short = '6', long)]
    ipv6: bool,

    /// アプリケーションをWindowsサービスとしてインストールします。
    #[arg(long)]
    install: bool,

    /// Windowsサービスをアンインストールします。
    #[arg(long)]
    uninstall: bool,

    /// Restart the Windows service.
    #[arg(long)]
    restart: bool,
}

/// アプリケーションのメインエントリーポイント。
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Windowsサービスとして実行するための特別な引数チェック。
    // `windows-service`クレートは、`--service`引数でサービスディスパッチャを起動します。
    // このチェックは、clapによる通常の引数解析の前に行う必要があります。
    if env::args().any(|arg| arg == "--service" || arg == "-s") {
        // サービス実行ループに入り、サービスが停止するまで制御を返しません。
        run_service()?;
        return Ok(());
    }

    // サービスモードでない場合は、通常のCLIアプリケーションとして引数を解析します。
    let args = Args::parse();

    // 解析された引数に基づいて、対応する処理モードに分岐します。
    // 各モードは排他的に実行されるため、if-else ifで順に評価します。
    if args.install {
        install_service()?;
    } else if args.uninstall {
        uninstall_service()?;
    } else if args.restart {
        restart_service()?;
    } else if args.add {
        // アカウント追加モード
        add_mode()?;
    } else if let Some(id) = args.remove {
        // アカウント削除モード
        remove_mode(&id)?;
    } else if let Some(id_arg) = args.edit {
        // アカウント編集モード
        // `edit`引数は値を持つ場合と持たない場合があります。
        // `default_missing_value`により、値なしの場合は特殊な文字列が入ります。
        let target = if id_arg == "_INTERACTIVE_" {
            // `--edit` のようにIDが指定されなかった場合、対話的な選択モードに入ります。
            None
        } else {
            // `--edit <ID>` のようにIDが指定された場合、そのIDをターゲットにします。
            Some(id_arg)
        };
        edit_mode(target)?;
    } else if args.view || args.list {
        // 設定表示モード (`--view` と `--list` は同じ機能です)
        view_mode()?;
    } else if args.notify || args.ipv4 || args.ipv6 {
        // 即時通知モード
        // -n (--notify) はIPv4/v6両方を有効化
        // -4 (--ipv4) はIPv4のみを有効化
        // -6 (--ipv6) はIPv6のみを有効化
        let use_ipv4 = args.notify || args.ipv4;
        let use_ipv6 = args.notify || args.ipv6;
        notify_now_mode(use_ipv4, use_ipv6)?;
    } else {
        // 引数が何も指定されなかった場合のデフォルト動作。
        // ユーザーが設定を手軽に変更できるよう、対話的な編集モードを開始します。
        edit_mode(None)?;
    }
    Ok(())
}

/// 新しいアカウント設定を追加するための対話モードを処理します。
fn add_mode() -> io::Result<()> {
    println!("{}", get_msg("add_title"));

    // MasterIDの入力
    let master_id = ask_with_default(get_msg("master_id_prompt"), "", false)?;

    // 重複チェック
    let configs = load_all_configs().unwrap_or_else(|_| Vec::new());
    if configs.iter().any(|c| c.master_id == master_id) {
        println!(
            "{}",
            get_msg("account_exists_fmt").replace("{}", &master_id)
        );
        return Ok(());
    }

    // MasterIDの基本的な形式を検証します。
    if !master_id.starts_with("mydns") {
        println!("{}", get_msg("invalid_master_id_prefix"));
        return Ok(());
    }

    // パスワードの入力
    let password = ask_with_default(get_msg("password_prompt"), "", true)?;

    // IPv4/IPv6通知の入力
    let ipv4_notify = ask_yes_no_simple(get_msg("ipv4_notify_prompt"), true)?;
    let ipv6_notify = ask_yes_no_simple(get_msg("ipv6_notify_prompt"), true)?;

    // 新しい設定をレジストリに保存します。
    match save_to_registry(&master_id, &password, ipv4_notify, ipv6_notify) {
        Ok(_) => {
            let msg = get_msg("add_success");
            println!("{}", msg);
            log_info(&format!("Account added: {}", master_id));
        }
        Err(e) => {
            let msg = get_msg("registry_save_fail_fmt").replace("{}", &e.to_string());
            println!("{}", msg);
            log_error(&format!("Failed to add account {}: {}", master_id, e));
        }
    }

    Ok(())
}

/// 既存のアカウント設定を編集するための対話モードを処理します。
/// `target_id`が`Some`の場合はそのアカウントを直接編集し、`None`の場合はリストから選択させます。
fn edit_mode(target_id: Option<String>) -> io::Result<()> {
    println!("{}", get_msg("edit_title"));

    let configs = load_all_configs().unwrap_or_else(|_| Vec::new());
    if configs.is_empty() {
        // 設定が一つもない場合は、新規追加モードに移行するか確認します。
        if ask_yes_no(get_msg("no_accounts_add_prompt"), true)? {
            return add_mode();
        } else {
            return Ok(());
        }
    }

    // 編集対象の設定を決定します。
    let config_to_edit = match target_id {
        Some(id) => {
            // コマンドラインでIDが指定された場合、そのIDを持つ設定を探します。
            if let Some(c) = configs.iter().find(|c| c.master_id == id) {
                c.clone()
            } else {
                // 指定されたIDが見つからなかった場合。
                println!("{}", get_msg("account_not_found_fmt").replace("{}", &id));
                return Ok(());
            }
        }
        None => {
            // IDが指定されなかった場合、対話的に選択させます。
            println!("{}", get_msg("select_account_prompt"));
            for (i, c) in configs.iter().enumerate() {
                println!("{}. {}", i + 1, c.master_id);
            }
            print!("{}", get_msg("select_account_index_prompt"));
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let input = input.trim();

            // ユーザーはリストの番号か、MasterID文字列のどちらでも入力できます。
            if let Ok(index) = input.parse::<usize>() {
                if index > 0 && index <= configs.len() {
                    configs[index - 1].clone()
                } else {
                    println!("{}", get_msg("invalid_selection"));
                    return Ok(());
                }
            } else if let Some(c) = configs.iter().find(|c| c.master_id == input) {
                c.clone()
            } else {
                println!("{}", get_msg("invalid_selection"));
                return Ok(());
            }
        }
    };

    println!(
        "{}",
        get_msg("edit_target_fmt").replace("{}", &config_to_edit.master_id)
    );

    // 各設定項目を、現在の値をデフォルトとしてユーザーに再入力させます。
    let password = ask_with_default(get_msg("password_prompt"), &config_to_edit.password, true)?;
    let ipv4_notify = ask_yes_no(get_msg("ipv4_notify_prompt"), config_to_edit.ipv4_notify)?;
    let ipv6_notify = ask_yes_no(get_msg("ipv6_notify_prompt"), config_to_edit.ipv6_notify)?;

    // 更新された設定を保存します。
    // MasterIDはレジストリのキー名であるため、変更はできません。
    match save_to_registry(
        &config_to_edit.master_id,
        &password,
        ipv4_notify,
        ipv6_notify,
    ) {
        Ok(_) => {
            let msg = get_msg("registry_save_success");
            println!("{}", msg);
            log_info(&format!("Account edited: {}", config_to_edit.master_id));
        }
        Err(e) => {
            let msg = get_msg("registry_save_fail_fmt").replace("{}", &e.to_string());
            println!("{}", msg);
            log_error(&format!(
                "Failed to edit account {}: {}",
                config_to_edit.master_id, e
            ));
        }
    }

    Ok(())
}

/// 指定されたIDのアカウント設定を削除する処理を行います。
fn remove_mode(id: &str) -> io::Result<()> {
    println!("{}", get_msg("remove_title"));

    // 破壊的な操作であるため、実行前に必ず確認を求めます。
    if ask_yes_no_simple(&get_msg("confirm_remove_fmt").replace("{}", id), false)? {
        match delete_config(id) {
            Ok(_) => {
                let msg = get_msg("remove_success");
                println!("{}", msg);
                log_info(&format!("Account removed: {}", id));
            }
            Err(e) => {
                let msg = get_msg("remove_fail_fmt").replace("{}", &e.to_string());
                println!("{}", msg);
                log_error(&format!("Failed to remove account {}: {}", id, e));
            }
        }
    } else {
        println!("{}", get_msg("operation_cancelled"));
    }
    Ok(())
}

/// デフォルト値付きでユーザーからの入力を求めるヘルパー関数。
/// ユーザーが何も入力せずにEnterキーを押した場合、`default`値が返されます。
/// `is_password`がtrueの場合、コンソールに入力がエコーバックされません。
fn ask_with_default(prompt: &str, default: &str, is_password: bool) -> io::Result<String> {
    // プロンプトのフォーマット文字列を国際化メッセージから取得します。
    let fmt = if is_password {
        get_msg("input_prompt_pw_fmt")
    } else {
        get_msg("input_prompt_fmt")
    };
    let fmt_new = get_msg("input_prompt_new_fmt");

    // プロンプトを表示します。
    if is_password {
        if default.is_empty() {
            print!("{}", fmt_new.replace("{}", prompt));
        } else {
            let masked_pw = mask_password(default); // パスワードはマスクして表示
            print!(
                "{}",
                fmt.replacen("{}", prompt, 1).replacen("{}", &masked_pw, 1)
            );
        }
    } else if default.is_empty() {
        print!("{}", fmt_new.replace("{}", prompt));
    } else {
        print!(
            "{}",
            fmt.replacen("{}", prompt, 1).replacen("{}", default, 1)
        );
    }
    io::stdout().flush()?;

    // ユーザーからの入力を読み取ります。
    let input = if is_password {
        read_password()? // rpasswordクレートを使い、安全にパスワードを読み取る
    } else {
        let mut buffer = String::new();
        io::stdin().read_line(&mut buffer)?;
        buffer
    };

    let trimmed = input.trim();
    // 入力が空であればデフォルト値を、そうでなければ入力された値を返します。
    if trimmed.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

/// パスワード文字列を、コンソール表示用にマスクします。
/// 機密情報が画面に平文で表示されるのを防ぎます。
fn mask_password(pw: &str) -> String {
    let len = pw.chars().count();
    if len == 0 {
        return get_msg("not_set").to_string();
    }
    // 短すぎるパスワードは、文字数すら推測されないように全てマスクします。
    if len <= 4 {
        return "*".repeat(len);
    }

    let mut chars: Vec<char> = pw.chars().collect();
    // ユーザーがパスワードが設定されていることを認識できるよう、最初・真ん中・最後の文字だけ表示します。
    for (i, c) in chars.iter_mut().enumerate() {
        if i != 0 && i != len - 1 && i != len / 2 {
            *c = '*';
        }
    }
    chars.into_iter().collect()
}

/// Yes/No形式の質問をユーザーに問いかけ、現在の設定値も表示します。
fn ask_yes_no(prompt: &str, default: bool) -> io::Result<bool> {
    let current_value = if default {
        get_msg("yes")
    } else {
        get_msg("no")
    };
    let hint = if default {
        // デフォルト値が大文字で表示されるヒント (Y/n)
        get_msg("yes_no_hint_true")
    } else {
        // (y/N)
        get_msg("yes_no_hint_false")
    };
    loop {
        print!(
            "{}",
            get_msg("yes_no_prompt_fmt")
                .replacen("{}", prompt, 1)
                .replacen("{}", current_value, 1)
                .replacen("{}", hint, 1)
        );
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let trimmed = input.trim().to_lowercase();

        if trimmed.is_empty() {
            // ユーザーがEnterキーのみを押した場合、デフォルト値を返します。
            return Ok(default);
        }

        match trimmed.as_str() {
            "y" => return Ok(true),
            "n" => return Ok(false),
            _ => println!("{}", get_msg("yes_no_invalid")),
        }
    }
}

/// 「現在の値」を表示しない、シンプルなYes/No形式の確認をユーザーに求めます。
fn ask_yes_no_simple(prompt: &str, default: bool) -> io::Result<bool> {
    let hint = if default {
        get_msg("yes_no_hint_true")
    } else {
        get_msg("yes_no_hint_false")
    };
    loop {
        print!(
            "{}",
            get_msg("confirm_prompt_fmt")
                .replacen("{}", prompt, 1)
                .replacen("{}", hint, 1)
        );
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let trimmed = input.trim().to_lowercase();

        if trimmed.is_empty() {
            return Ok(default);
        }

        match trimmed.as_str() {
            "y" => return Ok(true),
            "n" => return Ok(false),
            _ => println!("{}", get_msg("yes_no_invalid")),
        }
    }
}

/// 設定されているすべてのアカウント情報を、整形されたリストとして表示します。
fn view_mode() -> io::Result<()> {
    println!("{}", get_msg("view_title"));
    let configs = load_all_configs().unwrap_or_else(|_| Vec::new());

    if configs.is_empty() {
        println!("{}", get_msg("view_no_accounts"));
        return Ok(());
    }

    for config in &configs {
        // 各値を指定の長さにフォーマットする
        let master_id_val = format!("{:<11.11}", &config.master_id);
        let password_val = format!("{:<11.11}", mask_password(&config.password));
        let ipv4_val = format!(
            "{:<3.3}",
            if config.ipv4_notify {
                get_msg("yes")
            } else {
                get_msg("no")
            }
        );
        let ipv6_val = format!(
            "{:<3.3}",
            if config.ipv6_notify {
                get_msg("yes")
            } else {
                get_msg("no")
            }
        );

        // 国際化されたフォーマット文字列を使って、一行の情報を組み立てて表示します。
        println!(
            "{}",
            get_msg("view_list_fmt")
                .replace("{id}", &master_id_val)
                .replace("{pw}", &password_val)
                .replace("{v4}", &ipv4_val)
                .replace("{v6}", &ipv6_val)
        );
    }

    Ok(())
}

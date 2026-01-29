//! Windowsサービスとしての登録、実行、管理を行うモジュール。
//!
//! このモジュールは、`windows-service`クレートを使用してサービスのライフサイクルを管理し、
//! `windows`クレート（Win32 API）を直接呼び出してサービスのインストールやアンインストールを行います。

// --- 内部モジュール ---
use crate::i18n::{get_msg, get_msg_en};
use crate::logging::{log_error, log_info};
use crate::notify::perform_notification;
use crate::registry::load_all_configs;

// --- 標準ライブラリ ---
use std::ffi::OsString;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

// --- 外部クレート ---
// Win32 APIを直接呼び出すためのクレート。サービス管理API（SCM）の操作に使用。
use windows::Win32::Foundation::{ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_NOT_ACTIVE};
use windows::Win32::System::Services::{
    CloseServiceHandle, ControlService, CreateServiceW, DeleteService, OpenSCManagerW,
    OpenServiceW, QueryServiceStatus, SC_HANDLE, SC_MANAGER_ALL_ACCESS, SC_MANAGER_CREATE_SERVICE,
    SERVICE_ALL_ACCESS, SERVICE_AUTO_START, SERVICE_CONTROL_STOP, SERVICE_ERROR_NORMAL,
    SERVICE_QUERY_STATUS, SERVICE_START, SERVICE_STATUS, SERVICE_STOP, SERVICE_STOPPED,
    SERVICE_WIN32_OWN_PROCESS, StartServiceW,
};
use windows::core::HRESULT;
// Windowsサービスの実装を簡略化するためのクレート。
use windows_service::define_windows_service;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;

/// Windowsサービスとして登録される際のサービス名。
const SERVICE_NAME: &str = "MyDNSAdapterService";
/// サービスを削除するために必要なアクセス権フラグ (`DELETE`)。
const DELETE: u32 = 0x00010000;

/// サービスを開始するためのエントリーポイント。
///
/// `windows-service`クレートの`service_dispatcher`を呼び出し、
/// OSからのサービス開始要求に応じて`ffi_service_main`を実行します。
pub fn run_service() -> windows_service::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

// `define_windows_service!`マクロは、`windows-service`クレートが提供するマクロです。
// これにより、純粋なRustの関数 (`service_main_logic`) を、Windowsのサービス制御マネージャ (SCM) が
// 呼び出すことができるFFI（Foreign Function Interface）互換のエントリーポイント関数
// (`ffi_service_main`) に変換します。この変換により、SCMからのライフサイクルイベントを
// Rustコード内で安全に処理できるようになります。
define_windows_service!(ffi_service_main, service_main_logic);

/// サービスのメインロジック。`ffi_service_main`から呼び出される、実質的なサービスのエントリーポイントです。
///
/// サービスの初期化、メインループの実行、終了処理をカプセル化した `run_service_loop_impl` を呼び出します。
/// `run_service_loop_impl` からエラーが返された場合（通常はサービスの初期化や実行中の回復不能なエラー）、
/// その内容をログに記録します。
///
/// # 引数
/// * `args` - サービス開始時にSCMから渡される引数。このアプリケーションでは現在使用していません。
fn service_main_logic(args: Vec<OsString>) {
    if let Err(e) = run_service_loop_impl(args) {
        // サービス実行中に予期せぬエラーが発生した場合、英語でログを記録する。
        // サービスはシステムアカウントで実行されることが多く、ユーザーのロケールが
        // 適用されるとは限らないため、安定して読める英語でログを出力します。
        log_error(&get_msg_en("log_service_failed_fmt").replace("{}", &e.to_string()));
    }
}

/// サービスのメインループとライフサイクル管理を実装する関数。
///
/// この関数は、サービスが「実行中」状態にある間、継続的に実行されます。
/// 1. 停止要求をハンドリングするための準備。
/// 2. SCMにサービスが「実行中」であることを通知。
/// 3. 設定を読み込み、初回通知を実行。
/// 4. メインループに入り、定期的な通知処理と停止要求の待機を繰り返す。
/// 5. 停止要求を受け取ったら、SCMにサービスが「停止」したことを通知して終了。
fn run_service_loop_impl(_args: Vec<OsString>) -> windows_service::Result<()> {
    // サービス停止要求を通知するためのチャネルを作成。
    let (shutdown_tx, shutdown_rx) = mpsc::channel();

    // OSからの制御イベント（停止、問い合わせなど）を処理するハンドラ。
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            // 停止または問い合わせイベントを受信した場合
            ServiceControl::Stop | ServiceControl::Interrogate => {
                // メインループに停止を通知する。送信エラーは無視する（既に停止処理中のため）。
                shutdown_tx.send(()).ok();
                ServiceControlHandlerResult::NoError
            }
            // その他のイベントは未実装として扱う。
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    // サービス制御ハンドラをOSに登録し、状態を報告するためのハンドルを取得。
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    // サービスの状態を「実行中」としてOSに通知。
    // これにより、サービス管理ツールなどでサービスが実行中として表示される。
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        // このサービスが受け入れる制御は「停止」のみ。
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    // サービス開始をログに記録。
    log_info(get_msg_en("log_service_started"));

    let configs = load_all_configs().unwrap_or_default();
    if configs.is_empty() {
        // 設定が一つも存在しない場合は、サービスを続行できないためエラーを記録し、停止する。
        log_error(get_msg_en("log_service_config_missing"));
        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(1), // Configuration error
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;
        return Ok(());
    }

    let client = reqwest::blocking::Client::new();

    // サービス開始時に、設定されているすべてのアカウントに対して一度通知を実行する。
    for config in &configs {
        perform_notification(&client, config);
    }

    // サービスのメインループ。
    loop {
        // `recv_timeout` を使用して、定期的な処理と停止要求の待機を同時に行う。
        // 5分間待機し、その間に停止要求が来なければタイムアウトして処理を続行する。
        match shutdown_rx.recv_timeout(Duration::from_secs(5 * 60)) {
            // 停止要求を受信したか、チャネルが切断された場合はループを抜ける。
            Ok(_) | Err(mpsc::RecvTimeoutError::Disconnected) => break, // Stop
            // タイムアウトした場合（5分経過した場合）、定期通知処理を実行する。
            Err(mpsc::RecvTimeoutError::Timeout) => {
                for config in &configs {
                    perform_notification(&client, config);
                }
            }
        }
    }

    // サービス停止をログに記録。
    log_info(get_msg_en("log_service_stopping"));
    // サービスの状態を「停止」としてOSに通知。
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

/// サービスをWindowsにインストールし、開始する。
///
/// 管理者権限が必要です。
pub fn install_service() -> Result<(), Box<dyn std::error::Error>> {
    // 管理者権限があるかチェックする。
    if !is_elevated() {
        return Err(get_msg("admin_required_install").into());
    }

    // 自身の実行可能ファイルのパスを取得し、サービス実行用の引数 `--service` を付与する。
    let exe_path = std::env::current_exe()?;
    let bin_path_with_arg = format!("\"{}\" --service", exe_path.display());

    let bin_path_hstring = windows::core::HSTRING::from(bin_path_with_arg);
    let service_name_hstring = windows::core::HSTRING::from(SERVICE_NAME);
    let display_name_hstring = windows::core::HSTRING::from("MyDNS.JP IP Notifier");

    // Win32 APIを呼び出すため、unsafeブロックを使用する。
    // 各APIの引数はドキュメントに従って正しく設定されており、ハンドルは適切にクローズされるため安全。
    unsafe {
        let scm_handle = OpenSCManagerW(None, None, SC_MANAGER_CREATE_SERVICE)?;

        let service_handle = CreateServiceW(
            scm_handle,
            &service_name_hstring,
            &display_name_hstring,
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            &bin_path_hstring,
            None,
            None,
            None,
            None,
            None,
        )?;

        println!(
            "{}",
            get_msg("service_installing_fmt").replace("{}", SERVICE_NAME)
        );
        // サービスを即時開始する。
        StartServiceW(service_handle, None)?;
        println!(
            "{}",
            get_msg("service_installed_fmt").replace("{}", SERVICE_NAME)
        );

        // 開いたハンドルをクローズする。エラーは無視。
        let _ = CloseServiceHandle(service_handle);
        let _ = CloseServiceHandle(scm_handle);
    }

    Ok(())
}

/// サービスを停止し、Windowsからアンインストールする。
///
/// 管理者権限が必要です。
pub fn uninstall_service() -> Result<(), Box<dyn std::error::Error>> {
    // 管理者権限があるかチェックする。
    if !is_elevated() {
        return Err(get_msg("admin_required_uninstall").into());
    }

    let service_name_hstring = windows::core::HSTRING::from(SERVICE_NAME);

    unsafe {
        // Win32 APIを呼び出すため、unsafeブロックを使用する。
        // 各APIの引数はドキュメントに従って正しく設定されており、ハンドルは適切にクローズされるため安全。
        let scm_handle = OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)?;

        let service_handle = match OpenServiceW(
            scm_handle,
            &service_name_hstring,
            SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE,
        ) {
            Ok(handle) => handle,
            // サービスが存在しないエラーの場合は、アンインストール済みとみなし正常終了。
            Err(e) if e.code().0 == HRESULT::from(ERROR_SERVICE_DOES_NOT_EXIST).0 => {
                println!(
                    "{}",
                    get_msg("service_not_installed_fmt").replace("{}", SERVICE_NAME)
                );
                let _ = CloseServiceHandle(scm_handle);
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };

        // サービスが実行中であれば停止する。
        stop_service(service_handle)?;

        // サービスを削除する。
        DeleteService(service_handle)?;
        println!(
            "{}",
            get_msg("service_uninstalled_fmt").replace("{}", SERVICE_NAME)
        );

        // 開いたハンドルをクローズする。エラーは無視。
        let _ = CloseServiceHandle(service_handle);
        let _ = CloseServiceHandle(scm_handle);
    }

    Ok(())
}

/// サービスを再起動する。
///
/// 管理者権限が必要です。
pub fn restart_service() -> Result<(), Box<dyn std::error::Error>> {
    if !is_elevated() {
        return Err(get_msg("admin_required_restart").into());
    }

    let service_name_hstring = windows::core::HSTRING::from(SERVICE_NAME);

    unsafe {
        // Win32 APIを呼び出すため、unsafeブロックを使用する。
        // 各APIの引数はドキュメントに従って正しく設定されており、ハンドルは適切にクローズされるため安全。
        let scm_handle = OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)?;

        let service_handle = match OpenServiceW(
            scm_handle,
            &service_name_hstring,
            SERVICE_STOP | SERVICE_START | SERVICE_QUERY_STATUS,
        ) {
            Ok(handle) => handle,
            // サービスが存在しないエラーの場合は、メッセージを表示して正常終了。
            Err(e) if e.code().0 == HRESULT::from(ERROR_SERVICE_DOES_NOT_EXIST).0 => {
                println!(
                    "{}",
                    get_msg("service_not_installed_fmt").replace("{}", SERVICE_NAME)
                );
                let _ = CloseServiceHandle(scm_handle);
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };

        // サービスを停止し、その後開始する。
        stop_service(service_handle)?;
        StartServiceW(service_handle, None)?;
        println!("{}", get_msg("service_restarted_successfully"));

        // 開いたハンドルをクローズする。エラーは無視。
        let _ = CloseServiceHandle(service_handle);
        let _ = CloseServiceHandle(scm_handle);
    }

    Ok(())
}

/// 現在のプロセスが管理者権限で実行されているかどうかを判定します。
///
/// SCMへのフルアクセスを試みることで、権限の有無を簡易的にチェックします。
fn is_elevated() -> bool {
    unsafe {
        match OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS) {
            Ok(handle) => {
                // SCMハンドルが正常に開けた場合、管理者権限があると判断できる。
                // 開いたハンドルは必ずクローズする。
                let _ = CloseServiceHandle(handle);
                true
            }
            Err(_) => {
                // ハンドルが開けなかった場合（通常はアクセス拒否エラー）、管理者権限がないと判断する。
                false
            }
        }
    }
}

/// 指定されたサービスハンドルに対応するサービスを停止するヘルパー関数。
///
/// サービスが完全に停止するまで待機します。
unsafe fn stop_service(service_handle: SC_HANDLE) -> windows::core::Result<()> {
    unsafe {
        // サービスの状態を受け取るための構造体。
        let mut service_status: SERVICE_STATUS = std::mem::zeroed();
        // サービスに停止コントロールコードを送信する。
        match ControlService(service_handle, SERVICE_CONTROL_STOP, &mut service_status) {
            Ok(()) => {
                // 停止コマンドが受け入れられた場合
                println!(
                    "{}",
                    get_msg("service_stopping_fmt").replace("{}", SERVICE_NAME)
                );
                // サービスが完全に停止するのを待つループ。
                loop {
                    // 現在のサービス状態を問い合わせる。
                    QueryServiceStatus(service_handle, &mut service_status)?;
                    // 状態が `SERVICE_STOPPED` になったらループを抜ける。
                    if service_status.dwCurrentState == SERVICE_STOPPED {
                        println!("{}", get_msg("service_stopped"));
                        break;
                    }
                    // 停止するまで1秒待機する。
                    println!("{}", get_msg("service_waiting_stop"));
                    thread::sleep(Duration::from_secs(1));
                }
            }
            // サービスが既に停止している場合はエラーではないので、メッセージを表示して正常終了。
            Err(e) if e.code().0 == HRESULT::from(ERROR_SERVICE_NOT_ACTIVE).0 => {
                println!("{}", get_msg("service_not_running"));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

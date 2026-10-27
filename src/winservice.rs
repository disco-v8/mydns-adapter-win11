//! Windowsサービスとしての登録、実行、管理を行うモジュール。
//!
//! このモジュールは、`windows-service`クレートを使用してサービスのライフサイクルを管理し、
//! `windows`クレート（Win32 API）を直接呼び出してサービスのインストールやアンインストールを行います。

// --- 内部モジュール ---
use crate::i18n::{get_msg, get_msg_en};
use crate::logging::{log_error, log_info};
use crate::notify::{
    NOTIFICATION_CYCLE_TIMEOUT, build_client, next_notification_at, notify_configs,
};
use crate::registry::load_all_configs;

// --- 標準ライブラリ ---
use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

// --- 外部クレート ---
// Win32 APIを直接呼び出すためのクレート。サービス管理API（SCM）の操作に使用。
use windows::Win32::Foundation::{
    ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_NOT_ACTIVE, ERROR_TIMEOUT,
};
use windows::Win32::System::Services::{
    CloseServiceHandle, ControlService, CreateServiceW, DeleteService, OpenSCManagerW,
    OpenServiceW, QueryServiceStatus, SC_HANDLE, SC_MANAGER_ALL_ACCESS, SC_MANAGER_CREATE_SERVICE,
    SERVICE_ALL_ACCESS, SERVICE_AUTO_START, SERVICE_CONTROL_STOP, SERVICE_ERROR_NORMAL,
    SERVICE_QUERY_STATUS, SERVICE_START, SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE,
    SERVICE_STOP, SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_WIN32_OWN_PROCESS, StartServiceW,
};
use windows::core::HRESULT;
// Windowsサービスの実装を簡略化するためのクレート。
use windows_service::define_windows_service;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::service_dispatcher;

/// Windowsサービスとして登録される際のサービス名。
const SERVICE_NAME: &str = "MyDNSAdapterService";
/// サービスを削除するために必要なアクセス権フラグ (`DELETE`)。
const DELETE: u32 = 0x00010000;
const STOP_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const STOP_WAIT_POLL_INTERVAL: Duration = Duration::from_millis(250);
const STOP_PENDING_WAIT_HINT: Duration = Duration::from_secs(20);

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
    let stop_requested = Arc::new(AtomicBool::new(false));
    let event_stop_requested = Arc::clone(&stop_requested);
    let stop_status_handle = Arc::new(OnceLock::<ServiceStatusHandle>::new());
    let event_status_handle = Arc::clone(&stop_status_handle);

    // OSからの制御イベント（停止、問い合わせなど）を処理するハンドラ。
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        handle_control_event(
            control_event,
            &shutdown_tx,
            &event_stop_requested,
            |status| {
                if let Some(status_handle) = event_status_handle.get()
                    && let Err(error) = status_handle.set_service_status(status)
                {
                    log_error(&format!("Failed to report STOP_PENDING: {error}"));
                }
            },
        )
    };

    // サービス制御ハンドラをOSに登録し、状態を報告するためのハンドルを取得。
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;
    let _ = stop_status_handle.set(status_handle);

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
    if stop_requested.load(Ordering::Acquire) {
        status_handle.set_service_status(stop_pending_status())?;
    }

    // サービス開始をログに記録。
    log_info(get_msg_en("log_service_started"));

    let client = match build_client() {
        Ok(client) => client,
        Err(error) => {
            log_error(&format!("Failed to create HTTP client: {error}"));
            status_handle.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Stopped,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::Win32(1),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            })?;
            return Ok(());
        }
    };

    let mut next_start_at = Instant::now();
    loop {
        let now = Instant::now();
        if next_start_at > now {
            match shutdown_rx.recv_timeout(next_start_at - now) {
                Ok(_) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
        if stop_requested.load(Ordering::Acquire) {
            break;
        }

        let cycle_started = Instant::now();
        match load_all_configs() {
            Ok(configs) if configs.is_empty() => {
                log_info(get_msg_en("log_service_config_missing"));
            }
            Ok(configs) => {
                let report = notify_configs(
                    &client,
                    &configs,
                    true,
                    true,
                    cycle_started + NOTIFICATION_CYCLE_TIMEOUT,
                    || stop_requested.load(Ordering::Acquire),
                );
                if report.failed > 0 {
                    log_error(&format!(
                        "Notification cycle: {} succeeded, {} failed, {} attempted.",
                        report.succeeded, report.failed, report.attempted
                    ));
                }
                if report.deadline_exceeded {
                    log_error("Notification cycle reached its time limit.");
                }
            }
            Err(error) => log_error(&format!(
                "Failed to load notification configuration: {error}"
            )),
        }

        next_start_at = next_notification_at(cycle_started);
    }

    // サービス停止をログに記録。
    log_info(get_msg_en("log_service_stopping"));
    // サービスの状態を「停止」としてOSに通知。
    status_handle.set_service_status(stopped_status())?;

    Ok(())
}

fn stop_pending_status() -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StopPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 1,
        wait_hint: STOP_PENDING_WAIT_HINT,
        process_id: None,
    }
}

fn stopped_status() -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }
}

fn handle_control_event<F>(
    control_event: ServiceControl,
    shutdown_tx: &mpsc::Sender<()>,
    stop_requested: &AtomicBool,
    report_status: F,
) -> ServiceControlHandlerResult
where
    F: FnOnce(ServiceStatus),
{
    match control_event {
        ServiceControl::Stop => {
            stop_requested.store(true, Ordering::Release);
            report_status(stop_pending_status());
            shutdown_tx.send(()).ok();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        STOP_WAIT_POLL_INTERVAL, StopWaitDecision, handle_control_event, restart_after_stop,
        should_send_stop_control, stop_pending_status, stop_wait_decision, stopped_status,
    };
    use std::cell::Cell;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::time::Duration;
    use windows::Win32::System::Services::{
        SERVICE_RUNNING, SERVICE_STOP_PENDING, SERVICE_STOPPED,
    };
    use windows_service::service::ServiceControl;
    use windows_service::service::ServiceState;
    use windows_service::service_control_handler::ServiceControlHandlerResult;

    #[test]
    fn interrogate_does_not_request_shutdown() {
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let stop_requested = AtomicBool::new(false);

        let result = handle_control_event(
            ServiceControl::Interrogate,
            &shutdown_tx,
            &stop_requested,
            |_| {},
        );

        assert!(matches!(result, ServiceControlHandlerResult::NoError));
        assert!(!stop_requested.load(Ordering::Acquire));
        assert!(shutdown_rx.try_recv().is_err());
    }

    #[test]
    fn stop_requests_shutdown() {
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let stop_requested = AtomicBool::new(false);

        let mut reported_status = None;
        let result = handle_control_event(
            ServiceControl::Stop,
            &shutdown_tx,
            &stop_requested,
            |status| reported_status = Some(status),
        );

        assert!(matches!(result, ServiceControlHandlerResult::NoError));
        assert!(stop_requested.load(Ordering::Acquire));
        assert!(shutdown_rx.try_recv().is_ok());
        assert_eq!(reported_status.unwrap(), stop_pending_status());
    }

    #[test]
    fn service_reports_pending_then_stopped_statuses() {
        let pending = stop_pending_status();
        assert_eq!(pending.current_state, ServiceState::StopPending);
        assert!(pending.controls_accepted.is_empty());
        assert_eq!(pending.checkpoint, 1);
        assert!(!pending.wait_hint.is_zero());

        let stopped = stopped_status();
        assert_eq!(stopped.current_state, ServiceState::Stopped);
        assert_eq!(stopped.checkpoint, 0);
        assert!(stopped.wait_hint.is_zero());
    }

    #[test]
    fn stop_control_is_not_resent_while_service_is_stopping() {
        assert!(!should_send_stop_control(SERVICE_STOPPED));
        assert!(!should_send_stop_control(SERVICE_STOP_PENDING));
        assert!(should_send_stop_control(SERVICE_RUNNING));
    }

    #[test]
    fn restart_waits_through_pending_until_stopped() {
        assert_eq!(
            stop_wait_decision(SERVICE_STOP_PENDING, Duration::from_secs(5)),
            StopWaitDecision::Wait(STOP_WAIT_POLL_INTERVAL)
        );
        assert_eq!(
            stop_wait_decision(SERVICE_STOPPED, Duration::ZERO),
            StopWaitDecision::Stopped
        );
        assert_eq!(
            stop_wait_decision(SERVICE_STOP_PENDING, Duration::ZERO),
            StopWaitDecision::TimedOut
        );
    }

    #[test]
    fn restart_starts_only_after_stop_completes() {
        let stopped = Cell::new(false);
        let result = restart_after_stop(
            || {
                stopped.set(true);
                Ok::<(), ()>(())
            },
            || {
                assert!(stopped.get());
                Ok(())
            },
        );

        assert!(result.is_ok());
    }

    #[test]
    fn restart_does_not_start_if_stop_fails() {
        let mut start_called = false;
        let result = restart_after_stop(
            || Err::<(), _>("stop failed"),
            || {
                start_called = true;
                Ok(())
            },
        );

        assert_eq!(result, Err("stop failed"));
        assert!(!start_called);
    }
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
        restart_after_stop(
            || stop_service(service_handle),
            || StartServiceW(service_handle, None),
        )?;
        println!("{}", get_msg("service_restarted_successfully"));

        // 開いたハンドルをクローズする。エラーは無視。
        let _ = CloseServiceHandle(service_handle);
        let _ = CloseServiceHandle(scm_handle);
    }

    Ok(())
}

fn restart_after_stop<Stop, Start, E>(stop: Stop, start: Start) -> Result<(), E>
where
    Stop: FnOnce() -> Result<(), E>,
    Start: FnOnce() -> Result<(), E>,
{
    stop()?;
    start()
}

fn should_send_stop_control(current_state: SERVICE_STATUS_CURRENT_STATE) -> bool {
    current_state != SERVICE_STOPPED && current_state != SERVICE_STOP_PENDING
}

#[derive(Debug, PartialEq, Eq)]
enum StopWaitDecision {
    Stopped,
    Wait(Duration),
    TimedOut,
}

fn stop_wait_decision(
    current_state: SERVICE_STATUS_CURRENT_STATE,
    remaining: Duration,
) -> StopWaitDecision {
    if current_state == SERVICE_STOPPED {
        StopWaitDecision::Stopped
    } else if remaining.is_zero() {
        StopWaitDecision::TimedOut
    } else {
        StopWaitDecision::Wait(remaining.min(STOP_WAIT_POLL_INTERVAL))
    }
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
        let mut service_status: SERVICE_STATUS = std::mem::zeroed();
        QueryServiceStatus(service_handle, &mut service_status)?;
        if service_status.dwCurrentState == SERVICE_STOPPED {
            println!("{}", get_msg("service_not_running"));
            return Ok(());
        }

        if should_send_stop_control(service_status.dwCurrentState) {
            match ControlService(service_handle, SERVICE_CONTROL_STOP, &mut service_status) {
                Ok(()) => println!(
                    "{}",
                    get_msg("service_stopping_fmt").replace("{}", SERVICE_NAME)
                ),
                Err(error) if error.code().0 == HRESULT::from(ERROR_SERVICE_NOT_ACTIVE).0 => {
                    QueryServiceStatus(service_handle, &mut service_status)?;
                    if service_status.dwCurrentState == SERVICE_STOPPED {
                        println!("{}", get_msg("service_not_running"));
                        return Ok(());
                    }
                    if service_status.dwCurrentState != SERVICE_STOP_PENDING {
                        return Err(error);
                    }
                }
                Err(error) => return Err(error),
            }
        }

        println!("{}", get_msg("service_waiting_stop"));
        let deadline = Instant::now() + STOP_WAIT_TIMEOUT;
        loop {
            QueryServiceStatus(service_handle, &mut service_status)?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            match stop_wait_decision(service_status.dwCurrentState, remaining) {
                StopWaitDecision::Stopped => {
                    println!("{}", get_msg("service_stopped"));
                    return Ok(());
                }
                StopWaitDecision::TimedOut => {
                    return Err(windows::core::Error::new(
                        HRESULT::from(ERROR_TIMEOUT),
                        "Timed out waiting for the service to stop",
                    ));
                }
                StopWaitDecision::Wait(duration) => thread::sleep(duration),
            }
        }
    }
}

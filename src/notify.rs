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
use std::time::{Duration, Instant};

pub const NOTIFICATION_INTERVAL: Duration = Duration::from_secs(5 * 60);
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
pub const NOTIFICATION_CYCLE_TIMEOUT: Duration = Duration::from_secs(4 * 60);

pub fn next_notification_at(cycle_started: Instant) -> Instant {
    cycle_started + NOTIFICATION_INTERVAL
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct NotificationReport {
    pub attempted: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub interrupted: bool,
    pub deadline_exceeded: bool,
}

#[derive(Clone, Copy)]
struct NotificationPlan<'a> {
    use_ipv4: bool,
    use_ipv6: bool,
    endpoints: [&'a str; 2],
    deadline: Instant,
}

impl NotificationReport {
    pub fn is_success(&self) -> bool {
        self.attempted > 0
            && self.succeeded == self.attempted
            && self.failed == 0
            && !self.interrupted
            && !self.deadline_exceeded
    }

    fn merge(&mut self, other: Self) {
        self.attempted += other.attempted;
        self.succeeded += other.succeeded;
        self.failed += other.failed;
        self.interrupted |= other.interrupted;
        self.deadline_exceeded |= other.deadline_exceeded;
    }
}

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
    let configs = load_all_configs().map_err(|error| {
        log_error(&format!(
            "Failed to load notification configuration: {error}"
        ));
        io::Error::other(format!(
            "Failed to load notification configuration: {error}"
        ))
    })?;
    if configs.is_empty() {
        log_error(get_msg_en("log_config_missing"));
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            get_msg_en("log_config_missing"),
        ));
    }

    let client = build_client()
        .map_err(|error| io::Error::other(format!("Failed to create HTTP client: {error}")))?;
    let report = notify_configs(
        &client,
        &configs,
        use_ipv4,
        use_ipv6,
        Instant::now() + NOTIFICATION_CYCLE_TIMEOUT,
        || false,
    );

    if report.is_success() {
        log_info(get_msg_en("log_notify_finish"));
        Ok(())
    } else {
        let message = format!(
            "Immediate notification incomplete: {} succeeded, {} failed, {} attempted",
            report.succeeded, report.failed, report.attempted
        );
        log_error(&message);
        Err(io::Error::other(message))
    }
}

/// ひとつのアカウント設定に基づいて、IPアドレスの通知を実行します。
///
/// この関数は「即時通知モード」とWindowsサービスの定期実行ループの両方から呼び出されます。
/// 引数で渡された`Config`構造体の`ipv4_notify`と`ipv6_notify`フラグをチェックし、
/// 有効になっているプロトコルの通知処理をそれぞれ呼び出します。
pub fn build_client() -> reqwest::Result<Client> {
    Client::builder()
        .connect_timeout(REQUEST_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
}

pub fn notify_configs<F>(
    client: &Client,
    configs: &[Config],
    use_ipv4: bool,
    use_ipv6: bool,
    deadline: Instant,
    should_stop: F,
) -> NotificationReport
where
    F: Fn() -> bool,
{
    notify_configs_with_endpoints(
        client,
        configs,
        NotificationPlan {
            use_ipv4,
            use_ipv6,
            endpoints: [
                "https://ipv4.mydns.jp/login.html",
                "https://ipv6.mydns.jp/login.html",
            ],
            deadline,
        },
        should_stop,
        notify,
    )
}

fn notify_configs_with_endpoints<F, S>(
    client: &Client,
    configs: &[Config],
    plan: NotificationPlan<'_>,
    should_stop: F,
    mut send_request: S,
) -> NotificationReport
where
    F: Fn() -> bool,
    S: FnMut(&Client, &str, &str, &str, Duration) -> reqwest::Result<()>,
{
    let mut report = NotificationReport::default();
    for config in configs {
        let mut selected = config.clone();
        selected.ipv4_notify &= plan.use_ipv4;
        selected.ipv6_notify &= plan.use_ipv6;
        report.merge(perform_notification(
            client,
            &selected,
            plan.endpoints,
            plan.deadline,
            &should_stop,
            &mut send_request,
        ));
        if report.interrupted || report.deadline_exceeded {
            break;
        }
    }
    report
}

fn perform_notification<F>(
    client: &Client,
    config: &Config,
    endpoints: [&str; 2],
    deadline: Instant,
    should_stop: &F,
    send_request: &mut impl FnMut(&Client, &str, &str, &str, Duration) -> reqwest::Result<()>,
) -> NotificationReport
where
    F: Fn() -> bool,
{
    let mut report = NotificationReport::default();
    for (enabled, url, failure_key) in [
        (config.ipv4_notify, endpoints[0], "log_ipv4_fail_fmt"),
        (config.ipv6_notify, endpoints[1], "log_ipv6_fail_fmt"),
    ] {
        if !enabled {
            continue;
        }
        if should_stop() {
            report.interrupted = true;
            break;
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            report.deadline_exceeded = true;
            log_error("Notification cycle deadline exceeded; remaining requests skipped.");
            break;
        }

        report.attempted += 1;
        let timeout = remaining.min(REQUEST_TIMEOUT);
        match send_request(client, url, &config.master_id, &config.password, timeout) {
            Ok(()) => report.succeeded += 1,
            Err(error) => {
                report.failed += 1;
                let message = get_msg_en(failure_key).replace("{}", &error.to_string());
                log_error(&format!("[{}] {}", config.master_id, message));
            }
        }
    }
    report
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
fn notify(
    client: &Client,
    url: &str,
    id: &str,
    pw: &str,
    timeout: Duration,
) -> reqwest::Result<()> {
    // Basic認証情報を付与してGETリクエストを送信します。
    let res = client
        .get(url)
        .basic_auth(id, Some(pw))
        .timeout(timeout)
        .send()?;
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

#[cfg(test)]
mod tests {
    use super::{
        NOTIFICATION_INTERVAL, NotificationPlan, NotificationReport, next_notification_at, notify,
        notify_configs, notify_configs_with_endpoints,
    };
    use crate::registry::Config;
    use reqwest::blocking::Client;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    fn mock_server(response: &'static str, delay: Duration) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 1024];
            let _ = stream.read(&mut request);
            if !delay.is_zero() {
                thread::sleep(delay);
            }
            let _ = stream.write_all(response.as_bytes());
        });
        (format!("http://{address}/"), server)
    }

    fn delayed_mock_server(
        response: &'static str,
        delay: Duration,
    ) -> (String, mpsc::Receiver<()>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (request_received_tx, request_received_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 1024];
            let _ = stream.read(&mut request);
            request_received_tx.send(()).unwrap();
            thread::sleep(delay);
            let _ = stream.write_all(response.as_bytes());
        });
        (format!("http://{address}/"), request_received_rx, server)
    }

    #[test]
    fn empty_report_is_not_success() {
        assert!(!NotificationReport::default().is_success());
    }

    #[test]
    fn any_failed_request_makes_report_unsuccessful() {
        let report = NotificationReport {
            attempted: 2,
            succeeded: 1,
            failed: 1,
            ..NotificationReport::default()
        };

        assert!(!report.is_success());
    }

    #[test]
    fn all_successful_requests_make_report_successful() {
        let report = NotificationReport {
            attempted: 2,
            succeeded: 2,
            ..NotificationReport::default()
        };

        assert!(report.is_success());
    }

    #[test]
    fn http_success_is_accepted() {
        let (url, server) = mock_server(
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            Duration::ZERO,
        );

        assert!(
            notify(
                &Client::new(),
                &url,
                "mydns-test",
                "test-password",
                Duration::from_secs(2)
            )
            .is_ok()
        );
        server.join().unwrap();
    }

    #[test]
    fn http_error_is_reported_as_failure() {
        let (url, server) = mock_server(
            "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            Duration::ZERO,
        );

        assert!(
            notify(
                &Client::new(),
                &url,
                "mydns-test",
                "test-password",
                Duration::from_secs(2)
            )
            .is_err()
        );
        server.join().unwrap();
    }

    #[test]
    fn request_timeout_returns_control_to_caller() {
        let (url, server) = mock_server(
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            Duration::from_millis(300),
        );

        assert!(
            notify(
                &Client::new(),
                &url,
                "mydns-test",
                "test-password",
                Duration::from_millis(50)
            )
            .is_err()
        );
        server.join().unwrap();
    }

    #[test]
    fn pending_stop_skips_notification_requests() {
        let config = Config {
            master_id: "mydns-test".to_string(),
            password: "test-password".to_string(),
            ipv4_notify: true,
            ipv6_notify: true,
        };
        let report = notify_configs(
            &Client::new(),
            &[config],
            true,
            true,
            Instant::now() + Duration::from_secs(1),
            || true,
        );

        assert!(report.interrupted);
        assert_eq!(report.attempted, 0);
    }

    #[test]
    fn stop_after_one_request_prevents_the_next_request() {
        let (url, request_received, server) = delayed_mock_server(
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            Duration::from_millis(200),
        );
        let stop_requested = Arc::new(AtomicBool::new(false));
        let config = Config {
            master_id: "mydns-test".to_string(),
            password: "test-password".to_string(),
            ipv4_notify: true,
            ipv6_notify: true,
        };
        let notification_stop = Arc::clone(&stop_requested);
        let notification = thread::spawn(move || {
            notify_configs_with_endpoints(
                &Client::new(),
                &[config],
                NotificationPlan {
                    use_ipv4: true,
                    use_ipv6: true,
                    endpoints: [&url, &url],
                    deadline: Instant::now() + Duration::from_secs(2),
                },
                || notification_stop.load(Ordering::Acquire),
                notify,
            )
        });

        request_received
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        stop_requested.store(true, Ordering::Release);
        let report = notification.join().unwrap();
        server.join().unwrap();
        assert_eq!(report.attempted, 1);
        assert_eq!(report.succeeded, 1);
        assert!(report.interrupted);
    }

    #[test]
    fn next_notification_keeps_five_minute_start_anchor() {
        let cycle_started = Instant::now();
        let cycle_finished = cycle_started + Duration::from_secs(2 * 60);
        let next_start = next_notification_at(cycle_started);

        assert_eq!(next_start, cycle_started + NOTIFICATION_INTERVAL);
        assert_eq!(
            next_start.duration_since(cycle_finished),
            Duration::from_secs(3 * 60)
        );
    }
}

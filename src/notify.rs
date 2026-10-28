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
use crate::registry_load_error;
use reqwest::StatusCode;
use reqwest::blocking::Client;
use std::fmt;
use std::io;
use std::time::{Duration, Instant};

pub const NOTIFICATION_INTERVAL: Duration = Duration::from_secs(5 * 60);
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
pub const NOTIFICATION_CYCLE_TIMEOUT: Duration = Duration::from_secs(4 * 60);
const SUCCESS_PHRASE: [&str; 6] = ["login", "and", "ip", "address", "notify", "ok"];

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

#[derive(Debug, PartialEq, Eq)]
enum NotificationError {
    Authentication(StatusCode),
    Server(StatusCode),
    Http(StatusCode),
    UnexpectedBody(StatusCode),
    Communication(&'static str),
}

impl fmt::Display for NotificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authentication(status) => {
                write!(formatter, "authentication failed (HTTP {status})")
            }
            Self::Server(status) => write!(formatter, "MyDNS.JP server error (HTTP {status})"),
            Self::Http(status) => write!(formatter, "HTTP request rejected (HTTP {status})"),
            Self::UnexpectedBody(status) => {
                write!(
                    formatter,
                    "unrecognized notification response (HTTP {status})"
                )
            }
            Self::Communication(reason) => write!(formatter, "communication error ({reason})"),
        }
    }
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
    run_immediate_notification(load_all_configs, |configs| {
        let client = build_client()
            .map_err(|error| io::Error::other(format!("Failed to create HTTP client: {error}")))?;
        Ok(notify_configs(
            &client,
            configs,
            use_ipv4,
            use_ipv6,
            Instant::now() + NOTIFICATION_CYCLE_TIMEOUT,
            || false,
        ))
    })
}

fn run_immediate_notification<Load, Send>(load_configs: Load, send: Send) -> io::Result<()>
where
    Load: FnOnce() -> windows::core::Result<Vec<Config>>,
    Send: FnOnce(&[Config]) -> io::Result<NotificationReport>,
{
    log_info(get_msg_en("log_notify_start"));
    let configs = load_configs().map_err(|error| {
        let error = registry_load_error(error);
        log_error(&format!(
            "Failed to load notification configuration: {error}"
        ));
        io::Error::new(
            error.kind(),
            format!("Failed to load notification configuration: {error}"),
        )
    })?;
    if configs.is_empty() {
        log_error(get_msg_en("log_config_missing"));
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            get_msg_en("log_config_missing"),
        ));
    }

    let report = send(&configs)?;

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
    S: FnMut(&Client, &str, &str, &str, Duration) -> Result<(), NotificationError>,
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
    send_request: &mut impl FnMut(&Client, &str, &str, &str, Duration) -> Result<(), NotificationError>,
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
) -> Result<(), NotificationError> {
    // Basic認証情報を付与してGETリクエストを送信します。
    let res = client
        .get(url)
        .basic_auth(id, Some(pw))
        .timeout(timeout)
        .send()
        .map_err(classify_communication_error)?;
    let status = res.status();
    if !status.is_success() {
        return Err(
            if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                NotificationError::Authentication(status)
            } else if status.is_server_error() {
                NotificationError::Server(status)
            } else {
                NotificationError::Http(status)
            },
        );
    }

    let final_url = res.url().clone();
    let peer = res
        .remote_addr()
        .map_or_else(|| "unknown".to_string(), |address| address.ip().to_string());
    let body = res.text().map_err(classify_communication_error)?;
    if !has_success_marker(&body) {
        log_error(&format!(
            "[{}] {}",
            id,
            describe_unexpected_response(url, &final_url, &peer, status, body.len())
        ));
        return Err(NotificationError::UnexpectedBody(status));
    }

    let msg = get_msg_en("log_notify_status_fmt")
        .replacen("{}", url, 1)
        .replacen("{}", &status.to_string(), 1);
    log_info(&format!("[{}] {}", id, msg));
    Ok(())
}

/// 本文・認証情報・クエリを含まない、想定外応答の診断行を作成します。
fn describe_unexpected_response(
    requested: &str,
    final_url: &reqwest::Url,
    peer: &str,
    status: StatusCode,
    body_bytes: usize,
) -> String {
    let final_text = format!(
        "{}://{}{}",
        final_url.scheme(),
        final_url.host_str().unwrap_or("?"),
        final_url.path()
    );
    format!(
        "Unrecognized response diagnostic: requested={requested} final={final_text} same_url={} peer={peer} status={} body_bytes={body_bytes}",
        final_text == requested,
        status.as_u16()
    )
}

fn has_success_marker(body: &str) -> bool {
    let tokens = body
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    if tokens.iter().any(|token| is_negation(token)) {
        return false;
    }

    let phrase_match = tokens
        .windows(SUCCESS_PHRASE.len())
        .any(|found| found.iter().map(String::as_str).eq(SUCCESS_PHRASE));
    let status_tokens = body
        .split(|character: char| {
            !character.is_ascii_alphanumeric() && !matches!(character, '.' | '+' | '-' | '/')
        })
        .filter(|token| !token.is_empty())
        .map(|token| token.trim_end_matches('.').to_ascii_lowercase())
        .collect::<Vec<_>>();
    let status_match = status_tokens
        .windows(3)
        .any(|found| found[0] == "login" && found[1] == "status" && found[2] == "1");

    phrase_match || status_match
}

fn is_negation(token: &str) -> bool {
    matches!(
        token,
        "not" | "no" | "failed" | "failure" | "error" | "invalid" | "denied"
    )
}

fn classify_communication_error(error: reqwest::Error) -> NotificationError {
    if error.is_timeout() {
        NotificationError::Communication("timeout")
    } else if error.is_connect() {
        NotificationError::Communication("connection failed")
    } else {
        NotificationError::Communication("request or response read failed")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        NOTIFICATION_INTERVAL, NotificationError, NotificationPlan, NotificationReport,
        has_success_marker, next_notification_at, notify, notify_configs,
        notify_configs_with_endpoints, run_immediate_notification,
    };
    use crate::registry::Config;
    use reqwest::{StatusCode, blocking::Client};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    fn mock_server(
        response: impl Into<String> + Send + 'static,
        delay: Duration,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let response = response.into();
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
        response: impl Into<String> + Send + 'static,
        delay: Duration,
    ) -> (String, mpsc::Receiver<()>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let response = response.into();
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

    fn http_response(status: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
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
    fn immediate_notification_distinguishes_empty_denied_and_failed_loads() {
        let empty =
            run_immediate_notification(|| Ok(vec![]), |_| panic!("must not send")).unwrap_err();
        assert_eq!(empty.kind(), std::io::ErrorKind::NotFound);
        for (code, expected_kind) in [
            (
                windows::Win32::Foundation::ERROR_ACCESS_DENIED,
                std::io::ErrorKind::PermissionDenied,
            ),
            (
                windows::Win32::Foundation::ERROR_INVALID_DATA,
                std::io::ErrorKind::Other,
            ),
        ] {
            let error = run_immediate_notification(
                || Err(windows::core::Error::from_hresult(code.into())),
                |_| panic!("must not send"),
            )
            .unwrap_err();
            assert_eq!(error.kind(), expected_kind);
            assert!(error.to_string().contains("Failed to load"));
            if expected_kind == std::io::ErrorKind::PermissionDenied {
                assert!(error.to_string().contains("elevated administrator"));
            }
        }
    }

    #[test]
    fn immediate_result_fails_for_partial_total_or_zero_notifications() {
        for (attempted, succeeded, failed, success) in [
            (2, 2, 0, true),
            (2, 1, 1, false),
            (2, 0, 2, false),
            (0, 0, 0, false),
        ] {
            let result = run_immediate_notification(
                || Ok(vec![Config::default()]),
                |_| {
                    Ok(NotificationReport {
                        attempted,
                        succeeded,
                        failed,
                        ..NotificationReport::default()
                    })
                },
            );
            assert_eq!(result.is_ok(), success);
        }
    }

    #[test]
    fn protocol_selection_intersects_account_flags_and_continues_after_failure() {
        let configs = [
            Config {
                master_id: "mydns-first".into(),
                ipv4_notify: true,
                ipv6_notify: false,
                ..Config::default()
            },
            Config {
                master_id: "mydns-second".into(),
                ipv4_notify: true,
                ipv6_notify: true,
                ..Config::default()
            },
        ];
        for (use_ipv4, use_ipv6, expected) in [
            (
                true,
                false,
                vec![("mydns-first", "v4"), ("mydns-second", "v4")],
            ),
            (false, true, vec![("mydns-second", "v6")]),
            (
                true,
                true,
                vec![
                    ("mydns-first", "v4"),
                    ("mydns-second", "v4"),
                    ("mydns-second", "v6"),
                ],
            ),
        ] {
            let mut observed = vec![];
            let report = notify_configs_with_endpoints(
                &Client::new(),
                &configs,
                NotificationPlan {
                    use_ipv4,
                    use_ipv6,
                    endpoints: ["v4", "v6"],
                    deadline: Instant::now() + Duration::from_secs(2),
                },
                || false,
                |_, url, id, _, _| {
                    observed.push((id.to_string(), url.to_string()));
                    if id == "mydns-first" {
                        Err(NotificationError::Authentication(StatusCode::UNAUTHORIZED))
                    } else {
                        Ok(())
                    }
                },
            );
            assert_eq!(
                observed,
                expected
                    .into_iter()
                    .map(|(id, url)| (id.to_string(), url.to_string()))
                    .collect::<Vec<_>>()
            );
            assert_eq!(report.attempted, observed.len());
            assert_eq!(report.failed, usize::from(use_ipv4));
            assert_eq!(report.succeeded, observed.len() - report.failed);
        }
    }

    fn capturing_server(
        response: String,
    ) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 2048];
            let length = stream.read(&mut request).unwrap_or(0);
            tx.send(String::from_utf8_lossy(&request[..length]).into_owned())
                .unwrap();
            let _ = stream.write_all(response.as_bytes());
        });
        (format!("http://{address}/"), rx, server)
    }

    fn authorization_header(request: &str) -> Option<String> {
        request.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("authorization")
                .then(|| value.trim().to_string())
        })
    }

    #[test]
    fn notification_request_carries_basic_authorization_header() {
        let (url, request, server) =
            capturing_server(http_response("200 OK", "Login and IP address notify OK."));

        notify(
            &Client::new(),
            &url,
            "mydns-test",
            "test-password",
            Duration::from_secs(2),
        )
        .unwrap();
        server.join().unwrap();

        // "mydns-test:test-password" をBase64化した固定値(ダミー資格情報)。
        assert_eq!(
            authorization_header(&request.recv().unwrap()).as_deref(),
            Some("Basic bXlkbnMtdGVzdDp0ZXN0LXBhc3N3b3Jk")
        );
    }

    #[test]
    fn cross_origin_redirect_does_not_forward_basic_authorization() {
        let (target_url, target_request, target) =
            capturing_server(http_response("200 OK", "Login and IP address notify OK."));
        let (url, first_request, first) = capturing_server(format!(
            "HTTP/1.1 302 Found\r\nLocation: {target_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ));

        let _ = notify(
            &Client::new(),
            &url,
            "mydns-test",
            "test-password",
            Duration::from_secs(2),
        );
        first.join().unwrap();
        target.join().unwrap();

        assert!(authorization_header(&first_request.recv().unwrap()).is_some());
        assert_eq!(authorization_header(&target_request.recv().unwrap()), None);
    }

    #[test]
    fn unexpected_response_diagnostic_excludes_query_and_credentials() {
        let final_url =
            reqwest::Url::parse("https://user:secret@www.mydns.jp/help?token=abc").unwrap();
        let line = super::describe_unexpected_response(
            "https://ipv4.mydns.jp/login.html",
            &final_url,
            "192.0.2.1",
            StatusCode::OK,
            42,
        );
        assert!(line.contains("final=https://www.mydns.jp/help same_url=false"));
        assert!(line.contains("body_bytes=42"));
        assert!(!line.contains("secret") && !line.contains("token"));
    }

    #[test]
    fn http_success_is_accepted() {
        let (url, server) = mock_server(
            http_response("200 OK", "Login and IP address notify OK."),
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
    fn ipv4_phrase_and_ipv6_status_are_independently_accepted() {
        let (ipv4_url, ipv4_server) = mock_server(
            http_response("200 OK", "Login and IP address notify OK."),
            Duration::ZERO,
        );
        let (ipv6_url, ipv6_server) =
            mock_server(http_response("200 OK", "login_status = 1"), Duration::ZERO);
        let config = Config {
            master_id: "mydns-test".to_string(),
            password: "test-password".to_string(),
            ipv4_notify: true,
            ipv6_notify: true,
        };

        let report = notify_configs_with_endpoints(
            &Client::new(),
            &[config],
            NotificationPlan {
                use_ipv4: true,
                use_ipv6: true,
                endpoints: [&ipv4_url, &ipv6_url],
                deadline: Instant::now() + Duration::from_secs(2),
            },
            || false,
            notify,
        );

        ipv4_server.join().unwrap();
        ipv6_server.join().unwrap();
        assert_eq!(report.attempted, 2);
        assert!(report.is_success());
    }

    #[test]
    fn ipv4_and_ipv6_ng_bodies_are_both_rejected() {
        let (ipv4_url, ipv4_server) =
            mock_server(http_response("200 OK", "Login failed."), Duration::ZERO);
        let (ipv6_url, ipv6_server) =
            mock_server(http_response("200 OK", "login status=10"), Duration::ZERO);
        let config = Config {
            master_id: "mydns-test".to_string(),
            password: "test-password".to_string(),
            ipv4_notify: true,
            ipv6_notify: true,
        };

        let report = notify_configs_with_endpoints(
            &Client::new(),
            &[config],
            NotificationPlan {
                use_ipv4: true,
                use_ipv6: true,
                endpoints: [&ipv4_url, &ipv6_url],
                deadline: Instant::now() + Duration::from_secs(2),
            },
            || false,
            notify,
        );

        ipv4_server.join().unwrap();
        ipv6_server.join().unwrap();
        assert_eq!(report.failed, 2);
        assert_eq!(report.succeeded, 0);
        assert!(!report.is_success());
    }

    #[test]
    fn official_success_markers_are_or_conditions_with_tolerant_formatting() {
        assert!(has_success_marker("Login and IP address notify OK"));
        assert!(has_success_marker("LOGIN\tAND, IP-address notify OK."));
        assert!(has_success_marker("login status=1"));
        assert!(has_success_marker("LOGIN_STATUS = 1"));
        assert!(!has_success_marker("not Login and IP address notify OK."));
        assert!(!has_success_marker("login status=10"));
        assert!(!has_success_marker("login failed; status=1"));
    }

    #[test]
    fn login_status_requires_exact_unsigned_one() {
        for value in ["-1", "+1", "1.5", "1/2", "10", "0", "1abc"] {
            assert!(
                !has_success_marker(&format!("login status={value}")),
                "value={value}"
            );
        }
        assert!(has_success_marker("login_status = 1."));
        assert!(has_success_marker("<p>login status=1</p>"));
    }

    #[test]
    fn http_error_is_reported_as_failure() {
        let body = "Login failed; secret response details.";
        let (url, server) = mock_server(http_response("401 Unauthorized", body), Duration::ZERO);

        let error = notify(
            &Client::new(),
            &url,
            "mydns-test",
            "test-password",
            Duration::from_secs(2),
        )
        .unwrap_err();
        assert_eq!(
            error,
            NotificationError::Authentication(StatusCode::UNAUTHORIZED)
        );
        let message = error.to_string();
        assert!(!message.contains(body));
        assert!(!message.contains("test-password"));
        server.join().unwrap();
    }

    #[test]
    fn successful_http_status_without_either_success_marker_is_rejected() {
        let (url, server) =
            mock_server(http_response("200 OK", "ordinary response"), Duration::ZERO);

        assert_eq!(
            notify(
                &Client::new(),
                &url,
                "mydns-test",
                "test-password",
                Duration::from_secs(2)
            ),
            Err(NotificationError::UnexpectedBody(StatusCode::OK))
        );
        server.join().unwrap();
    }

    #[test]
    fn server_error_is_distinguished_from_authentication_error() {
        for (status, expected) in [
            (
                "500 Internal Server Error",
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            ("503 Service Unavailable", StatusCode::SERVICE_UNAVAILABLE),
        ] {
            let (url, server) = mock_server(http_response(status, ""), Duration::ZERO);

            assert_eq!(
                notify(
                    &Client::new(),
                    &url,
                    "mydns-test",
                    "test-password",
                    Duration::from_secs(2)
                ),
                Err(NotificationError::Server(expected))
            );
            server.join().unwrap();
        }
    }

    #[test]
    fn other_http_errors_are_distinguished_from_authentication_errors() {
        let (url, server) = mock_server(
            "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            Duration::ZERO,
        );

        assert_eq!(
            notify(
                &Client::new(),
                &url,
                "mydns-test",
                "test-password",
                Duration::from_secs(2)
            ),
            Err(NotificationError::Http(StatusCode::BAD_REQUEST))
        );
        server.join().unwrap();
    }

    #[test]
    fn request_timeout_returns_control_to_caller() {
        let (url, server) = mock_server(
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            Duration::from_millis(300),
        );

        assert_eq!(
            notify(
                &Client::new(),
                &url,
                "mydns-test",
                "test-password",
                Duration::from_millis(50)
            ),
            Err(NotificationError::Communication("timeout"))
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
        let response = http_response("200 OK", "Login and IP address notify OK.");
        let (url, request_received, server) =
            delayed_mock_server(response, Duration::from_millis(200));
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

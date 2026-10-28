//! アプリケーションのログ記録機能を管理するモジュール。
//!
//! 実行ファイルと同じディレクトリに `mydns.log` という名前でログファイルを作成します。
//! ログファイルは指定された最大行数に達すると、古い行から自動的に削除されます（ログローテーション）。

use chrono::Local;
use std::collections::VecDeque;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use windows::Win32::Foundation::{
    BOOL, CloseHandle, HANDLE, HLOCAL, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW, REPLACEFILE_WRITE_THROUGH,
    ReplaceFileW,
};
use windows::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};
use windows::core::{HSTRING, PCWSTR};

/// ログファイルに保持する最大行数。これを超えると古いエントリが削除される。
const MAX_LOG_LINES: usize = 10_000;
const ROTATION_BATCH_LINES: usize = 100;
/// ログファイルの名前。
const LOG_FILE_NAME: &str = "mydns.log";
const LOG_MUTEX_NAME: &str = "Global\\MyDNSAdapterLogMutex";
const LOG_MUTEX_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BU)";
const LOG_MUTEX_WAIT: Duration = Duration::from_secs(15);
static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// ログファイルのフルパスを取得します。
///
/// ログファイルは、アプリケーションの実行ファイルと同じディレクトリに配置されます。
///
/// # Returns
///
/// 成功した場合はログファイルの `PathBuf` を、失敗した場合は `io::Error` を返します。
fn get_log_path() -> io::Result<PathBuf> {
    // 現在の実行ファイルのパスを取得
    let mut path = env::current_exe()?;
    // パスからファイル名部分を削除し、ディレクトリパスにする
    path.pop();
    // ディレクトリパスにログファイル名を追加
    path.push(LOG_FILE_NAME);
    Ok(path)
}

/// 情報レベルのメッセージをログファイルに記録します。
///
/// 内部で `log_to_file` を呼び出します。ファイルへの書き込みに失敗した場合は、
/// 標準エラー出力にフォールバックしてエラーメッセージを表示します。
pub fn log_info(message: &str) {
    report_log_failure(log_to_file("INFO", message));
}

/// エラーレベルのメッセージをログファイルに記録します。
///
/// 内部で `log_to_file` を呼び出します。ファイルへの書き込みに失敗した場合は、
/// 標準エラー出力にフォールバックしてエラーメッセージを表示します。
pub fn log_error(message: &str) {
    report_log_failure(log_to_file("ERROR", message));
}

fn log_to_file(level: &str, message: &str) -> io::Result<()> {
    let log_path = get_log_path()?;
    let now = Local::now().format("%Y-%m-%d %H:%M:%S");
    let sanitized = message.replace(['\r', '\n'], " ");
    append_log_record(
        &log_path,
        &format!("[{}] [{}] {}", now, level, sanitized),
        LOG_MUTEX_NAME,
    )
}

fn report_log_failure(result: io::Result<()>) {
    if let Err(error) = result {
        eprintln!(
            "[{}] [LOG-ERROR] Failed to write log: {}",
            Local::now().format("%Y-%m-%d %H:%M:%S"),
            error
        );
    }
}

fn append_log_record(path: &Path, line: &str, mutex_name: &str) -> io::Result<()> {
    let _guard = NamedMutexGuard::acquire(mutex_name)?;
    let mut state = load_log_state(path)?;
    ensure_trailing_newline(path, &mut state)?;

    let line = format!("{}\n", line.replace(['\r', '\n'], " "));
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(line.as_bytes())?;
    file.flush()?;
    file.sync_data()?;
    state.file_len += line.len() as u64;
    state.line_count += 1;

    if rotation_due(state.line_count) {
        state = rotate_log(path)?;
    }
    store_log_state(path, state)
}

#[derive(Clone, Copy)]
struct LogState {
    file_len: u64,
    line_count: usize,
}

fn rotation_due(line_count: usize) -> bool {
    line_count > MAX_LOG_LINES + ROTATION_BATCH_LINES
}

fn state_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    path.with_file_name(format!("{file_name}.state"))
}

fn load_log_state(path: &Path) -> io::Result<LogState> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(LogState {
                file_len: 0,
                line_count: 0,
            });
        }
        Err(error) => return Err(error),
    };
    let sidecar = state_path(path);
    if let Ok(contents) = fs::read_to_string(sidecar) {
        let mut fields = contents.split_whitespace();
        if let (Some(file_len), Some(line_count)) = (fields.next(), fields.next())
            && let (Ok(file_len), Ok(line_count)) = (file_len.parse(), line_count.parse())
            && fields.next().is_none()
            && file_len == metadata.len()
        {
            return Ok(LogState {
                file_len,
                line_count,
            });
        }
    }

    let line_count = BufReader::new(File::open(path)?)
        .lines()
        .try_fold(0usize, |count, line| line.map(|_| count + 1))?;
    Ok(LogState {
        file_len: metadata.len(),
        line_count,
    })
}

fn ensure_trailing_newline(path: &Path, state: &mut LogState) -> io::Result<()> {
    if state.file_len == 0 {
        return Ok(());
    }
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    file.seek(SeekFrom::End(-1))?;
    let mut last_byte = [0u8; 1];
    file.read_exact(&mut last_byte)?;
    if last_byte[0] != b'\n' {
        file.seek(SeekFrom::End(0))?;
        file.write_all(b"\n")?;
        file.flush()?;
        file.sync_data()?;
        state.file_len += 1;
    }
    Ok(())
}

fn rotate_log(path: &Path) -> io::Result<LogState> {
    let mut retained = VecDeque::with_capacity(MAX_LOG_LINES);
    for line in BufReader::new(File::open(path)?).lines() {
        let line = line?;
        if retained.len() == MAX_LOG_LINES {
            retained.pop_front();
        }
        retained.push_back(line);
    }

    let temp_path = temporary_path(path, "rotate");
    let result =
        write_lines_to_temp(&temp_path, &retained).and_then(|()| atomic_replace(&temp_path, path));
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result?;
    let file_len = fs::metadata(path)?.len();
    Ok(LogState {
        file_len,
        line_count: retained.len(),
    })
}

fn write_lines_to_temp(path: &Path, lines: &VecDeque<String>) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    for line in lines {
        writeln!(file, "{line}")?;
    }
    file.flush()?;
    file.sync_all()
}

fn store_log_state(path: &Path, state: LogState) -> io::Result<()> {
    let state_path = state_path(path);
    let temp_path = temporary_path(&state_path, "state");
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        writeln!(file, "{} {}", state.file_len, state.line_count)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        atomic_replace(&temp_path, &state_path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn temporary_path(path: &Path, suffix: &str) -> PathBuf {
    let file_name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    path.with_file_name(format!(
        ".{file_name}.{}.{}.{}.tmp",
        std::process::id(),
        sequence,
        suffix
    ))
}

fn atomic_replace(temp: &Path, target: &Path) -> io::Result<()> {
    let temp = HSTRING::from(temp.as_os_str());
    let target_wide = HSTRING::from(target.as_os_str());
    unsafe {
        if target.exists() {
            ReplaceFileW(
                PCWSTR(target_wide.as_ptr()),
                PCWSTR(temp.as_ptr()),
                None,
                REPLACEFILE_WRITE_THROUGH,
                None,
                None,
            )
        } else {
            MoveFileExW(
                PCWSTR(temp.as_ptr()),
                PCWSTR(target_wide.as_ptr()),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        }
    }
    .map_err(io::Error::other)
}

struct NamedMutexGuard(HANDLE);

impl NamedMutexGuard {
    fn acquire(name: &str) -> io::Result<Self> {
        let sddl = HSTRING::from(LOG_MUTEX_SDDL);
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                &sddl,
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(io::Error::other)?;

        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: BOOL(0),
        };
        let name = HSTRING::from(name);
        let mutex = unsafe { CreateMutexW(Some(&attributes), BOOL(0), &name) };
        unsafe {
            let _ = windows::Win32::Foundation::LocalFree(HLOCAL(descriptor.0));
        }
        let mutex = mutex.map_err(io::Error::other)?;
        match unsafe { WaitForSingleObject(mutex, LOG_MUTEX_WAIT.as_millis() as u32) } {
            WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Self(mutex)),
            WAIT_TIMEOUT => {
                unsafe {
                    let _ = CloseHandle(mutex);
                }
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out waiting for log mutex",
                ))
            }
            _ => {
                let error = io::Error::last_os_error();
                unsafe {
                    let _ = CloseHandle(mutex);
                }
                Err(error)
            }
        }
    }
}

impl Drop for NamedMutexGuard {
    fn drop(&mut self) {
        if let Err(error) = unsafe { ReleaseMutex(self.0) } {
            eprintln!("[LOG-ERROR] Failed to release log mutex: {error}");
        }
        if let Err(error) = unsafe { CloseHandle(self.0) } {
            eprintln!("[LOG-ERROR] Failed to close log mutex: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LOG_MUTEX_NAME, MAX_LOG_LINES, NamedMutexGuard, ROTATION_BATCH_LINES, append_log_record,
        rotation_due, state_path,
    };
    use std::collections::HashSet;
    use std::fs::{self, File};
    use std::io::{BufRead, BufReader, Write};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_PATH_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    const CHILD_LOG_PATH: &str = "MYDNS_ADAPTER_LOG_TEST_PATH";
    const CHILD_MUTEX_NAME: &str = "MYDNS_ADAPTER_LOG_TEST_MUTEX";
    const CHILD_PREFIX: &str = "MYDNS_ADAPTER_LOG_TEST_PREFIX";

    fn test_log_path(label: &str) -> PathBuf {
        let name = format!(
            "mydns-adapter-{label}-{}-{}.log",
            std::process::id(),
            TEST_PATH_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        std::env::temp_dir().join(name)
    }

    fn cleanup(path: &Path) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(state_path(path));
    }

    #[test]
    fn append_keeps_existing_lines() {
        let path = test_log_path("append");
        let mutex = format!("Global\\MyDNSAdapterLogTest-{}-append", std::process::id());
        cleanup(&path);

        append_log_record(&path, "first", &mutex).unwrap();
        append_log_record(&path, "second", &mutex).unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), "first\nsecond\n");
        cleanup(&path);
    }

    #[test]
    fn rotation_retains_the_newest_ten_thousand_lines() {
        let path = test_log_path("rotate");
        let mutex = format!("Global\\MyDNSAdapterLogTest-{}-rotate", std::process::id());
        cleanup(&path);
        {
            let mut file = File::create(&path).unwrap();
            for index in 0..(MAX_LOG_LINES + ROTATION_BATCH_LINES + 3) {
                writeln!(file, "old-{index}").unwrap();
            }
        }

        append_log_record(&path, "newest", &mutex).unwrap();
        let lines = BufReader::new(File::open(&path).unwrap())
            .lines()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(lines.len(), MAX_LOG_LINES);
        assert_eq!(
            lines.first().unwrap(),
            &format!("old-{}", ROTATION_BATCH_LINES + 4)
        );
        assert_eq!(lines.last().unwrap(), "newest");
        cleanup(&path);
    }

    #[test]
    fn rotation_uses_batch_slack_instead_of_rewriting_on_every_append() {
        assert!(!rotation_due(MAX_LOG_LINES + 1));
        assert!(!rotation_due(MAX_LOG_LINES + ROTATION_BATCH_LINES));
        assert!(rotation_due(MAX_LOG_LINES + ROTATION_BATCH_LINES + 1));
    }

    #[test]
    fn child_process_log_writer() {
        let (Ok(path), Ok(mutex), Ok(prefix)) = (
            std::env::var(CHILD_LOG_PATH),
            std::env::var(CHILD_MUTEX_NAME),
            std::env::var(CHILD_PREFIX),
        ) else {
            return;
        };
        for index in 0..100 {
            append_log_record(Path::new(&path), &format!("{prefix}-{index}"), &mutex).unwrap();
        }
    }

    #[test]
    fn named_mutex_serializes_separate_process_writers() {
        let path = test_log_path("process");
        let mutex = format!("Global\\MyDNSAdapterLogTest-{}-process", std::process::id());
        cleanup(&path);
        let executable = std::env::current_exe().unwrap();
        let mut children = Vec::new();
        for prefix in ["writer-a", "writer-b"] {
            children.push(
                Command::new(&executable)
                    .args(["--exact", "logging::tests::child_process_log_writer"])
                    .env(CHILD_LOG_PATH, &path)
                    .env(CHILD_MUTEX_NAME, &mutex)
                    .env(CHILD_PREFIX, prefix)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            );
        }
        for mut child in children {
            assert!(child.wait().unwrap().success());
        }

        let lines = BufReader::new(File::open(&path).unwrap())
            .lines()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let unique = lines.iter().collect::<HashSet<_>>();
        assert_eq!(lines.len(), 200);
        assert_eq!(unique.len(), 200);
        cleanup(&path);
    }

    #[test]
    fn global_mutex_is_available_to_the_current_cli_token() {
        drop(NamedMutexGuard::acquire(LOG_MUTEX_NAME).unwrap());
    }
}

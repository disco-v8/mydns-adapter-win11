//! アプリケーションのログ記録機能を管理するモジュール。
//!
//! 実行ファイルと同じディレクトリに `mydns.log` という名前でログファイルを作成します。
//! ログファイルは指定された最大行数に達すると、古い行から自動的に削除されます（ログローテーション）。

use chrono::Local;
use std::collections::VecDeque;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;

/// ログファイルに保持する最大行数。これを超えると古いエントリが削除される。
const MAX_LOG_LINES: usize = 10_000;
/// ログファイルの名前。
const LOG_FILE_NAME: &str = "mydns.log";

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
    if let Err(e) = log_to_file("INFO", message) {
        // ログファイルへの書き込みに失敗した場合のフォールバック処理。
        eprintln!(
            "[{}] [LOG-ERROR] Failed to write to log file: {}",
            Local::now().format("%Y-%m-%d %H:%M:%S"),
            e
        );
    }
}

/// エラーレベルのメッセージをログファイルに記録します。
///
/// 内部で `log_to_file` を呼び出します。ファイルへの書き込みに失敗した場合は、
/// 標準エラー出力にフォールバックしてエラーメッセージを表示します。
pub fn log_error(message: &str) {
    if let Err(e) = log_to_file("ERROR", message) {
        // ログファイルへの書き込みに失敗した場合のフォールバック処理。
        eprintln!(
            "[{}] [LOG-ERROR] Failed to write to log file: {}",
            Local::now().format("%Y-%m-%d %H:%M:%S"),
            e
        );
    }
}

/// ログファイルへの書き込みとローテーションを行う中心的な関数。
///
/// この関数は、以下の手順でログを追記・管理します。
/// 1. 既存のログファイルをすべて読み込む。
/// 2. 新しいログメッセージを末尾に追加する。
/// 3. ログの総行数が `MAX_LOG_LINES` を超えた場合、超過分を古い行から削除する。
/// 4. 更新されたログ内容でファイル全体を上書きする。
///
/// NOTE: この実装は、ログファイルが巨大になるとパフォーマンスに影響を与える可能性がありますが、
///       シンプルさと堅牢性を優先しています。
fn log_to_file(level: &str, message: &str) -> io::Result<()> {
    let log_path = get_log_path()?;
    let now = Local::now().format("%Y-%m-%d %H:%M:%S");
    let new_line = format!("[{}] [{}] {}", now, level, message);

    // 手順1: ファイルが存在する場合、すべての行を読み込んでVecDequeに格納する。
    let mut lines: VecDeque<String> = if log_path.exists() {
        let file = File::open(&log_path)?;
        let reader = BufReader::new(file);
        reader.lines().collect::<Result<_, _>>()?
    } else {
        // ファイルが存在しない場合は空のVecDequeから開始する。
        VecDeque::new()
    };

    // 手順2: 新しいログ行を末尾に追加する。
    lines.push_back(new_line);

    // 手順3: 行数が上限を超えている場合、古い行を先頭から削除する。
    if lines.len() > MAX_LOG_LINES {
        lines.drain(0..(lines.len() - MAX_LOG_LINES));
    }

    // 手順4: ファイルを上書きモードで開き、更新されたすべての行を書き戻す。
    // create(true): ファイルがなければ新規作成する。
    // truncate(true): ファイルを開く際に内容を空にする。
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&log_path)?;

    // 更新されたログの内容をファイルに書き込む。
    for line in lines {
        writeln!(file, "{}", line)?;
    }

    Ok(())
}

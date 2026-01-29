//! レジストリを介したアプリケーション設定の永続化を管理するモジュール。
//! 設定は `HKEY_LOCAL_MACHINE\Software\MyDNSAdapter` 以下に保存されます。

// --- Win32 API関連の定数や型をインポート ---
// Foundation: エラーコードなど基本的な型
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, WIN32_ERROR};
// System::Registry: レジストリ操作に必要な関数、定数、型
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SZ,
    REG_VALUE_TYPE, RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegEnumKeyExW, RegOpenKeyExW,
    RegQueryValueExW, RegSetValueExW,
};
// core: Win32 APIで文字列を扱うための型 (HSTRING, PCWSTRなど)
use windows::core::{HSTRING, PCWSTR, PWSTR, w};

/// アプリケーションの設定情報を保持する構造体。
///
/// レジストリの各サブキー（MasterIDごと）に対応し、
/// そのキーに含まれる値をフィールドとして持ちます。
#[derive(Clone, Debug, Default)]
pub struct Config {
    /// MyDNSのマスターID。レジストリではサブキー名として使用される。
    pub master_id: String,
    /// MyDNSのパスワード。
    pub password: String,
    /// IPv4アドレスの通知を有効にするかどうか。
    pub ipv4_notify: bool,
    /// IPv6アドレスの通知を有効にするかどうか。
    pub ipv6_notify: bool,
}

/// レジストリからすべての設定を読み込みます。
///
/// `HKLM\Software\MyDNSAdapter` の下の各サブキーを個別の設定として読み込み、
/// `Config` 構造体のベクターとして返します。
pub fn load_all_configs() -> windows::core::Result<Vec<Config>> {
    // Win32 APIを直接呼び出すため、unsafeブロックが必要。
    // 各API呼び出しはWindowsのドキュメントに従っており、
    // ハンドルのライフサイクル管理（オープンとクローズ）も適切に行われているため安全です。
    unsafe {
        let mut configs = Vec::new();
        let mut hkey_root: HKEY = HKEY::default();
        let subkey_root = w!("Software\\MyDNSAdapter");

        // ルートキーを開く
        let result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey_root, 0, KEY_READ, &mut hkey_root);
        // ルートキーが存在しない場合は、設定がまだないと判断し、空のVecを返す。
        if result == ERROR_FILE_NOT_FOUND {
            return Ok(configs);
        }
        // その他のエラーの場合はエラーを返す。
        result.ok()?;

        // ルートキーの下にあるサブキーを一つずつ列挙し、各設定を読み込むループ。
        let mut index = 0;
        loop {
            // RegEnumKeyExWは、指定されたインデックスのサブキー名を取得する。
            // バッファオーバーフローを避けるため、十分なサイズの固定長バッファを用意する。
            let mut name_buf = [0u16; 256];
            // name_lenは入力としてバッファサイズを、出力として実際のキー名の長さ（文字数）を受け取る。
            let mut name_len = name_buf.len() as u32;

            let res = RegEnumKeyExW(
                hkey_root,
                index,
                PWSTR(name_buf.as_mut_ptr()),
                &mut name_len,
                None,
                PWSTR::null(),
                None,
                None,
            );

            // 列挙するサブキーがなくなったらループを抜ける
            if res == ERROR_NO_MORE_ITEMS {
                break;
            }
            // 列挙中にエラーが発生した場合は、そのキーをスキップして次に進む
            if res != WIN32_ERROR(0) {
                index += 1;
                continue;
            }

            // 取得したキー名（UTF-16のu16スライス）をRustのStringに変換。
            let master_id = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            // RegOpenKeyExWで使うために、StringをHSTRINGに変換する。
            let sub_name = HSTRING::from(&master_id);
            let mut hkey_sub: HKEY = HKEY::default();

            // 列挙したサブキーを読み取り専用で開く。
            // サブキーを読み取りモードで開く
            if RegOpenKeyExW(
                hkey_root,
                PCWSTR(sub_name.as_ptr()),
                0,
                KEY_READ,
                &mut hkey_sub,
            ) == WIN32_ERROR(0)
            {
                // サブキーが開けたら、その中の各値（Password, IPv4Notifyなど）を取得する。
                // 値が存在しない場合も考慮し、unwrap_or_defaultでデフォルト値を使用する。
                let password = get_reg_string(hkey_sub, "Password").unwrap_or_default();
                let ipv4_notify_val = get_reg_dword(hkey_sub, "IPv4Notify").unwrap_or(0);
                let ipv6_notify_val = get_reg_dword(hkey_sub, "IPv6Notify").unwrap_or(0);

                // 取得した値からConfig構造体を生成し、ベクターに追加する。
                // 取得した設定をベクターに追加
                configs.push(Config {
                    master_id,
                    password,
                    ipv4_notify: ipv4_notify_val == 1,
                    ipv6_notify: ipv6_notify_val == 1,
                });
                // 開いたサブキーのハンドルをクローズする。
                let _ = RegCloseKey(hkey_sub);
            }
            index += 1;
        }
        // 開いたルートキーのハンドルをクローズする。エラーは無視。
        let _ = RegCloseKey(hkey_root);
        Ok(configs)
    }
}

/// レジストリキーからREG_SZ（文字列）型の値を取得します。
/// 値が存在しないか、型が異なる場合は空の文字列を返します。
fn get_reg_string(hkey: HKEY, name: &str) -> windows::core::Result<String> {
    // Win32 APIを直接呼び出すため、unsafeブロックが必要。
    // ポインタ操作はAPIの仕様に厳密に従っており、バッファサイズも事前に
    // 取得するため、メモリ安全性が確保されています。
    unsafe {
        let name_hstring = HSTRING::from(name);
        let mut buffer_size: u32 = 0;

        // 1. 必要なバッファサイズを取得するために、データポインタをnullにしてRegQueryValueExWを呼び出す。
        let res = RegQueryValueExW(
            hkey,
            &name_hstring,
            None,
            None,
            None,
            Some(&mut buffer_size),
        );
        // 値が存在しない、またはサイズが0の場合は空文字列を返す。
        if res != WIN32_ERROR(0) || buffer_size == 0 {
            return Ok(String::new());
        }

        // 2. 取得したサイズでバッファを確保し、再度RegQueryValueExWを呼び出して実際のデータを取得する。
        // バッファサイズはバイト単位なので、u16の数としては半分になる。
        let mut buffer: Vec<u16> = vec![0; (buffer_size / 2) as usize];
        let mut data_type = REG_VALUE_TYPE::default();
        let buffer_ptr = buffer.as_mut_ptr() as *mut u8;
        RegQueryValueExW(
            hkey,
            &name_hstring,
            None,
            Some(&mut data_type),
            Some(buffer_ptr),
            Some(&mut buffer_size),
        )
        .ok()?;

        // 型がREG_SZでない場合は、期待する型ではないので空文字列を返す。
        if data_type != REG_SZ {
            return Ok(String::new());
        }

        // バッファから文字列を生成する際、終端のNULL文字を含めないようにする。
        let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
        Ok(String::from_utf16_lossy(&buffer[..len]))
    }
}

/// レジストリキーからREG_DWORD（32ビット数値）型の値を取得します。
/// 値が存在しないか、型が異なる場合は0を返します。
fn get_reg_dword(hkey: HKEY, name: &str) -> windows::core::Result<u32> {
    // Win32 APIを直接呼び出すため、unsafeブロックが必要。
    // ポインタの指す先はスタック上の`data`変数であり、そのサイズも
    // 正しく指定しているため安全です。
    unsafe {
        let name_hstring = HSTRING::from(name);
        let mut data: u32 = 0;
        // DWORDのサイズは4バイト
        let mut data_size: u32 = std::mem::size_of::<u32>() as u32;
        let mut data_type = REG_VALUE_TYPE::default();

        let data_ptr = &mut data as *mut u32 as *mut u8;
        let res = RegQueryValueExW(
            hkey,
            &name_hstring,
            None,
            Some(&mut data_type),
            Some(data_ptr),
            Some(&mut data_size),
        );

        // 値が存在しない、または型がREG_DWORDでない場合は0を返す。
        if res != WIN32_ERROR(0) || data_type != REG_DWORD {
            return Ok(0);
        }

        Ok(data)
    }
}

/// 指定された設定をレジストリに保存します。
///
/// 既存のキーがあれば上書きし、なければ新規作成します。
pub fn save_to_registry(id: &str, pw: &str, v4: bool, v6: bool) -> windows::core::Result<()> {
    // Win32 APIを直接呼び出すため、unsafeブロックが必要。
    // 作成・オープンしたレジストリキーのハンドルは、関数の最後で
    // `RegCloseKey`により確実にクローズされるため安全です。
    unsafe {
        let mut hkey: HKEY = HKEY::default();
        // HKLM\Software\MyDNSAdapter\<id> のパスを作成
        let path = format!("Software\\MyDNSAdapter\\{}", id);
        let subkey = HSTRING::from(&path);

        // キーを作成または開く。書き込み権限を要求する。
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey.as_ptr()),
            0,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        )
        .ok()?;

        // 各値を設定する
        set_reg_string(hkey, w!("Password"), pw)?;
        set_reg_dword(hkey, w!("IPv4Notify"), if v4 { 1 } else { 0 })?;
        set_reg_dword(hkey, w!("IPv6Notify"), if v6 { 1 } else { 0 })?;

        // 開いたキーのハンドルをクローズする。
        let _ = RegCloseKey(hkey);
        Ok(())
    }
}

/// レジストリキーにREG_SZ（文字列）型の値を設定します。
fn set_reg_string(hkey: HKEY, name: PCWSTR, value: &str) -> windows::core::Result<()> {
    // Windows APIで使うために、文字列をNULL終端のUTF-16に変換する。
    // `chain(std::iter::once(0))` でNULL終端子を付与している。
    let v_utf16: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    // u16のスライスをu8のスライスに安全にキャストしてAPIに渡す。
    // `bytemuck`クレートは、このようなプリミティブ型間の安全なキャストを保証する。
    unsafe { RegSetValueExW(hkey, name, 0, REG_SZ, Some(bytemuck::cast_slice(&v_utf16))).ok() }
}

/// レジストリキーにREG_DWORD（32ビット数値）型の値を設定します。
fn set_reg_dword(hkey: HKEY, name: PCWSTR, value: u32) -> windows::core::Result<()> {
    // Win32 APIを直接呼び出すため、unsafeブロックが必要。
    // `bytemuck::cast_slice` を使ってu32の値を安全にバイトスライスに変換している。
    unsafe {
        // u32の値をu8のスライスに安全にキャストしてAPIに渡す。
        RegSetValueExW(
            hkey,
            name,
            0,
            REG_DWORD,
            Some(bytemuck::cast_slice(&[value])),
        )
        .ok()
    }
}

/// 指定されたIDの設定をレジストリから削除します。
pub fn delete_config(id: &str) -> windows::core::Result<()> {
    // Win32 APIを直接呼び出すため、unsafeブロックが必要。
    // オープンしたレジストリキーのハンドルは、関数の最後で
    // `RegCloseKey`により確実にクローズされるため安全です。
    unsafe {
        let mut hkey: HKEY = HKEY::default();
        let subkey_root = w!("Software\\MyDNSAdapter");

        // 親キーを書き込み権限で開く（サブキーの削除に必要）。
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey_root, 0, KEY_WRITE, &mut hkey).ok()?;

        let subkey_to_delete = HSTRING::from(id);
        // 指定されたサブキーを削除する。
        let res = RegDeleteKeyW(hkey, PCWSTR(subkey_to_delete.as_ptr()));

        let _ = RegCloseKey(hkey);
        res.ok()
    }
}

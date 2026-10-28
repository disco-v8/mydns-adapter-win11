//! レジストリを介したアプリケーション設定の永続化を管理するモジュール。
//! 設定は `HKEY_LOCAL_MACHINE\Software\MyDNSAdapter` 以下に保存されます。

// --- Win32 API関連の定数や型をインポート ---
// Foundation: エラーコードなど基本的な型
use crate::logging::log_error;
use std::collections::{HashMap, HashSet};
use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_INVALID_DATA, ERROR_NO_MORE_ITEMS, HLOCAL,
    LocalFree, WIN32_ERROR,
};
// System::Registry: レジストリ操作に必要な関数、定数、型
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
    CryptUnprotectData,
};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
};
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY,
    KEY_WRITE, REG_BINARY, REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SAM_FLAGS, REG_SZ,
    REG_VALUE_TYPE, RegCloseKey, RegCreateKeyExW, RegDeleteKeyExW, RegEnumKeyExW, RegOpenKeyExW,
    RegQueryValueExW, RegSetKeySecurity, RegSetValueExW,
};
// core: Win32 APIで文字列を扱うための型 (HSTRING, PCWSTRなど)
use windows::core::{HRESULT, HSTRING, PCWSTR, PWSTR, w};

const PROTECTED_PASSWORD_PREFIX: &[u8] = b"MYDNS-DPAPI\x01";

/// アプリケーションの設定情報を保持する構造体。
///
/// レジストリの各サブキー（MasterIDごと）に対応し、
/// そのキーに含まれる値をフィールドとして持ちます。
#[derive(Clone, Default, PartialEq, Eq)]
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

impl std::fmt::Debug for Config {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Config")
            .field("master_id", &self.master_id)
            .field("password", &"[REDACTED]")
            .field("ipv4_notify", &self.ipv4_notify)
            .field("ipv6_notify", &self.ipv6_notify)
            .finish()
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RegistryValue<T> {
    Missing,
    Present(T),
    InvalidType(u32),
    ApiError(u32),
    DecryptionError(u32),
    InvalidData,
}

#[derive(Debug, PartialEq, Eq)]
enum ConfigIssueKind {
    MissingValue,
    InvalidType { expected: &'static str, actual: u32 },
    ApiError(u32),
    DecryptionError(u32),
    InvalidData,
}

#[derive(Debug, PartialEq, Eq)]
struct ConfigIssue {
    master_id: String,
    field: &'static str,
    kind: ConfigIssueKind,
}

#[derive(Default)]
struct RegistryViewSnapshot {
    configs: HashMap<String, Config>,
    invalid_accounts: HashSet<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RegistryView {
    View32,
    View64,
}

impl RegistryView {
    fn access_flag(self) -> REG_SAM_FLAGS {
        match self {
            Self::View32 => KEY_WOW64_32KEY,
            Self::View64 => KEY_WOW64_64KEY,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::View32 => "32-bit",
            Self::View64 => "64-bit",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ViewSelectionError {
    InvalidAccount,
    Conflict,
}

/// レジストリからすべての設定を読み込みます。
///
/// `HKLM\Software\MyDNSAdapter` の下の各サブキーを個別の設定として読み込み、
/// `Config` 構造体のベクターとして返します。
pub fn load_all_configs() -> windows::core::Result<Vec<Config>> {
    load_registry_views(
        || read_registry_view(RegistryView::View32),
        || read_registry_view(RegistryView::View64),
    )
}

fn load_registry_views<Read32, Read64>(
    read32: Read32,
    read64: Read64,
) -> windows::core::Result<Vec<Config>>
where
    Read32: FnOnce() -> windows::core::Result<RegistryViewSnapshot>,
    Read64: FnOnce() -> windows::core::Result<RegistryViewSnapshot>,
{
    let view32 = read32()?;
    let view64 = read64()?;
    let has_accounts = !view32.configs.is_empty()
        || !view64.configs.is_empty()
        || !view32.invalid_accounts.is_empty()
        || !view64.invalid_accounts.is_empty();
    let configs = merge_registry_views(view32, view64);
    if configs.is_empty() && has_accounts {
        return Err(windows::core::Error::new(
            HRESULT::from(ERROR_INVALID_DATA),
            "No usable accounts: existing registry settings are invalid or conflicting. Inspect mydns.log.",
        ));
    }
    Ok(configs)
}

/// レジストリキーからREG_SZ（文字列）型の値を取得します。
fn read_registry_view(view: RegistryView) -> windows::core::Result<RegistryViewSnapshot> {
    unsafe {
        let mut root = HKEY::default();
        let open_result = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            w!("Software\\MyDNSAdapter"),
            0,
            KEY_READ | view.access_flag(),
            &mut root,
        );
        if open_result == ERROR_FILE_NOT_FOUND {
            return Ok(RegistryViewSnapshot::default());
        }
        open_result.ok()?;

        let result = (|| {
            let mut snapshot = RegistryViewSnapshot::default();
            let mut index = 0;
            loop {
                let mut name_buf = [0u16; 256];
                let mut name_len = name_buf.len() as u32;
                let enum_result = RegEnumKeyExW(
                    root,
                    index,
                    PWSTR(name_buf.as_mut_ptr()),
                    &mut name_len,
                    None,
                    PWSTR::null(),
                    None,
                    None,
                );
                if enum_result == ERROR_NO_MORE_ITEMS {
                    break;
                }
                enum_result.ok()?;

                let master_id = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                let subkey_name = HSTRING::from(&master_id);
                let mut subkey = HKEY::default();
                let subkey_result = RegOpenKeyExW(
                    root,
                    PCWSTR(subkey_name.as_ptr()),
                    0,
                    KEY_READ | view.access_flag(),
                    &mut subkey,
                );
                if subkey_result != WIN32_ERROR(0) {
                    if subkey_result == ERROR_ACCESS_DENIED {
                        return Err(access_denied_error());
                    }
                    snapshot.invalid_accounts.insert(normalize_id(&master_id));
                    log_error(&format!(
                        "Skipping registry account '{master_id}' in {} view: subkey open failed (Win32 {}).",
                        view.label(),
                        subkey_result.0
                    ));
                    index += 1;
                    continue;
                }

                let account = read_config_values(&master_id, subkey);
                let _ = RegCloseKey(subkey);
                match account {
                    Ok(config) => {
                        snapshot.configs.insert(normalize_id(&master_id), config);
                    }
                    Err(issues) => {
                        if issues.iter().any(is_access_denied_issue) {
                            return Err(access_denied_error());
                        }
                        snapshot.invalid_accounts.insert(normalize_id(&master_id));
                        for issue in issues {
                            log_config_issue(&issue, view);
                        }
                    }
                }
                index += 1;
            }
            Ok(snapshot)
        })();
        let _ = RegCloseKey(root);
        result
    }
}

fn merge_registry_views(view32: RegistryViewSnapshot, view64: RegistryViewSnapshot) -> Vec<Config> {
    let invalid_accounts = view32
        .invalid_accounts
        .union(&view64.invalid_accounts)
        .cloned()
        .collect::<HashSet<_>>();
    let account_ids = view32
        .configs
        .keys()
        .chain(view64.configs.keys())
        .cloned()
        .collect::<HashSet<_>>();
    let mut configs = Vec::new();

    for account_id in account_ids {
        if invalid_accounts.contains(&account_id) {
            continue;
        }
        match (
            view32.configs.get(&account_id),
            view64.configs.get(&account_id),
        ) {
            (Some(config32), Some(config64)) if config_values_equal(config32, config64) => {
                configs.push(config64.clone());
            }
            (Some(config32), Some(config64)) => {
                log_error(&format!(
                    "Skipping registry account '{}' because 32-bit and 64-bit views conflict.",
                    config32.master_id
                ));
                let _ = config64;
            }
            (Some(config), None) => configs.push(config.clone()),
            (None, Some(config)) => configs.push(config.clone()),
            (None, None) => {}
        }
    }
    configs.sort_by(|left, right| left.master_id.cmp(&right.master_id));
    configs
}

fn select_write_views(
    master_id: &str,
    view32: &RegistryViewSnapshot,
    view64: &RegistryViewSnapshot,
) -> Result<Option<Vec<RegistryView>>, ViewSelectionError> {
    let account_id = normalize_id(master_id);
    if view32.invalid_accounts.contains(&account_id)
        || view64.invalid_accounts.contains(&account_id)
    {
        return Err(ViewSelectionError::InvalidAccount);
    }

    match (
        view32.configs.get(&account_id),
        view64.configs.get(&account_id),
    ) {
        (Some(config32), Some(config64)) if config_values_equal(config32, config64) => {
            Ok(Some(vec![RegistryView::View32, RegistryView::View64]))
        }
        (Some(_), Some(_)) => Err(ViewSelectionError::Conflict),
        (Some(_), None) => Ok(Some(vec![RegistryView::View32])),
        (None, Some(_)) => Ok(Some(vec![RegistryView::View64])),
        (None, None) => Ok(None),
    }
}

fn normalize_id(master_id: &str) -> String {
    master_id.to_ascii_lowercase()
}

fn config_values_equal(left: &Config, right: &Config) -> bool {
    left.master_id.eq_ignore_ascii_case(&right.master_id)
        && left.password == right.password
        && left.ipv4_notify == right.ipv4_notify
        && left.ipv6_notify == right.ipv6_notify
}

fn read_config_values(master_id: &str, hkey: HKEY) -> Result<Config, Vec<ConfigIssue>> {
    let password = unsafe { read_password_value(hkey, "Password") };
    let ipv4 = unsafe { read_dword_value(hkey, "IPv4Notify") };
    let ipv6 = unsafe { read_dword_value(hkey, "IPv6Notify") };
    parse_config_values(master_id, password, ipv4, ipv6)
}

fn parse_config_values(
    master_id: &str,
    password: RegistryValue<String>,
    ipv4: RegistryValue<u32>,
    ipv6: RegistryValue<u32>,
) -> Result<Config, Vec<ConfigIssue>> {
    let mut issues = Vec::new();
    let empty_password = matches!(&password, RegistryValue::Present(value) if value.is_empty());
    let password = value_or_issue(master_id, "Password", "REG_SZ", password, &mut issues);
    let ipv4 = value_or_issue(master_id, "IPv4Notify", "REG_DWORD", ipv4, &mut issues);
    let ipv6 = value_or_issue(master_id, "IPv6Notify", "REG_DWORD", ipv6, &mut issues);
    let password = password.unwrap_or_default();
    let ipv4 = ipv4.unwrap_or_default();
    let ipv6 = ipv6.unwrap_or_default();

    if empty_password {
        issues.push(ConfigIssue {
            master_id: master_id.to_string(),
            field: "Password",
            kind: ConfigIssueKind::InvalidData,
        });
    }
    if ipv4 > 1 {
        issues.push(ConfigIssue {
            master_id: master_id.to_string(),
            field: "IPv4Notify",
            kind: ConfigIssueKind::InvalidData,
        });
    }
    if ipv6 > 1 {
        issues.push(ConfigIssue {
            master_id: master_id.to_string(),
            field: "IPv6Notify",
            kind: ConfigIssueKind::InvalidData,
        });
    }
    if !issues.is_empty() {
        return Err(issues);
    }

    Ok(Config {
        master_id: master_id.to_string(),
        password,
        ipv4_notify: ipv4 == 1,
        ipv6_notify: ipv6 == 1,
    })
}

fn value_or_issue<T: Default>(
    master_id: &str,
    field: &'static str,
    expected: &'static str,
    value: RegistryValue<T>,
    issues: &mut Vec<ConfigIssue>,
) -> Option<T> {
    match value {
        RegistryValue::Present(value) => Some(value),
        RegistryValue::Missing => {
            issues.push(ConfigIssue {
                master_id: master_id.to_string(),
                field,
                kind: ConfigIssueKind::MissingValue,
            });
            None
        }
        RegistryValue::InvalidType(actual) => {
            issues.push(ConfigIssue {
                master_id: master_id.to_string(),
                field,
                kind: ConfigIssueKind::InvalidType { expected, actual },
            });
            None
        }
        RegistryValue::ApiError(code) => {
            issues.push(ConfigIssue {
                master_id: master_id.to_string(),
                field,
                kind: ConfigIssueKind::ApiError(code),
            });
            None
        }
        RegistryValue::DecryptionError(code) => {
            issues.push(ConfigIssue {
                master_id: master_id.to_string(),
                field,
                kind: ConfigIssueKind::DecryptionError(code),
            });
            None
        }
        RegistryValue::InvalidData => {
            issues.push(ConfigIssue {
                master_id: master_id.to_string(),
                field,
                kind: ConfigIssueKind::InvalidData,
            });
            None
        }
    }
}

fn log_config_issue(issue: &ConfigIssue, view: RegistryView) {
    let reason = match issue.kind {
        ConfigIssueKind::MissingValue => "value is missing".to_string(),
        ConfigIssueKind::InvalidType { expected, actual } => {
            format!("expected {expected}, found registry type {actual}")
        }
        ConfigIssueKind::ApiError(code) => format!("registry API error {code}"),
        ConfigIssueKind::DecryptionError(code) => {
            format!("DPAPI decryption failed with error {code}")
        }
        ConfigIssueKind::InvalidData => "value is malformed".to_string(),
    };
    log_error(&format!(
        "Skipping registry account '{}' in {} view: {} {}.",
        issue.master_id,
        view.label(),
        issue.field,
        reason
    ));
}

fn is_access_denied_issue(issue: &ConfigIssue) -> bool {
    matches!(issue.kind, ConfigIssueKind::ApiError(code) if code == ERROR_ACCESS_DENIED.0)
}

fn access_denied_error() -> windows::core::Error {
    windows::core::Error::new(
        HRESULT::from(ERROR_ACCESS_DENIED),
        "Registry access denied.",
    )
}

unsafe fn read_password_value(hkey: HKEY, name: &str) -> RegistryValue<String> {
    let name = HSTRING::from(name);
    let mut value_type = REG_VALUE_TYPE::default();
    let mut buffer_size = 0;
    let result = unsafe {
        RegQueryValueExW(
            hkey,
            &name,
            None,
            Some(&mut value_type),
            None,
            Some(&mut buffer_size),
        )
    };
    if result == ERROR_FILE_NOT_FOUND {
        return RegistryValue::Missing;
    }
    if result != WIN32_ERROR(0) {
        return RegistryValue::ApiError(result.0);
    }
    if value_type != REG_SZ && value_type != REG_BINARY {
        return RegistryValue::InvalidType(value_type.0);
    }
    if value_type == REG_SZ && buffer_size % 2 != 0 {
        return RegistryValue::InvalidData;
    }
    if buffer_size == 0 {
        return if value_type == REG_SZ {
            RegistryValue::Present(String::new())
        } else {
            RegistryValue::InvalidData
        };
    }

    let mut buffer = vec![0u8; buffer_size as usize];
    let result = unsafe {
        RegQueryValueExW(
            hkey,
            &name,
            None,
            Some(&mut value_type),
            Some(buffer.as_mut_ptr()),
            Some(&mut buffer_size),
        )
    };
    if result == ERROR_FILE_NOT_FOUND {
        return RegistryValue::Missing;
    }
    if result != WIN32_ERROR(0) {
        return RegistryValue::ApiError(result.0);
    }
    if value_type != REG_SZ && value_type != REG_BINARY {
        return RegistryValue::InvalidType(value_type.0);
    }
    if buffer_size as usize > buffer.len() || (value_type == REG_SZ && buffer_size % 2 != 0) {
        return RegistryValue::InvalidData;
    }
    buffer.truncate(buffer_size as usize);
    if value_type == REG_SZ {
        if !buffer.len().is_multiple_of(2) {
            return RegistryValue::InvalidData;
        }
        let wide = bytemuck::try_cast_slice::<u8, u16>(&buffer);
        let Ok(wide) = wide else {
            return RegistryValue::InvalidData;
        };
        let length = wide
            .iter()
            .position(|character| *character == 0)
            .unwrap_or(wide.len());
        return match String::from_utf16(&wide[..length]) {
            Ok(value) => RegistryValue::Present(value),
            Err(_) => RegistryValue::InvalidData,
        };
    }

    match unprotect_password(&buffer) {
        Ok(password) => RegistryValue::Present(password),
        Err(error) => RegistryValue::DecryptionError(error.code().0 as u32),
    }
}

unsafe fn read_dword_value(hkey: HKEY, name: &str) -> RegistryValue<u32> {
    let name = HSTRING::from(name);
    let mut value = 0u32;
    let mut value_size = std::mem::size_of::<u32>() as u32;
    let mut value_type = REG_VALUE_TYPE::default();
    let result = unsafe {
        RegQueryValueExW(
            hkey,
            &name,
            None,
            Some(&mut value_type),
            Some(&mut value as *mut u32 as *mut u8),
            Some(&mut value_size),
        )
    };
    if result == ERROR_FILE_NOT_FOUND {
        return RegistryValue::Missing;
    }
    if result != WIN32_ERROR(0) {
        return RegistryValue::ApiError(result.0);
    }
    if value_type != REG_DWORD {
        return RegistryValue::InvalidType(value_type.0);
    }
    if value_size as usize != std::mem::size_of::<u32>() {
        return RegistryValue::InvalidData;
    }
    RegistryValue::Present(value)
}

/// 指定された設定をレジストリに保存します。
///
/// 既存のキーがあれば上書きし、なければ新規作成します。
pub fn save_to_registry(id: &str, pw: &str, v4: bool, v6: bool) -> windows::core::Result<()> {
    persist_after_password_protection(pw, protect_password, |protected_password| {
        let view32 = read_registry_view(RegistryView::View32)?;
        let view64 = read_registry_view(RegistryView::View64)?;
        let selected = select_write_views(id, &view32, &view64)
            .map_err(view_selection_error)?
            .unwrap_or_else(|| vec![RegistryView::View64]);

        for view in selected {
            write_config_to_view(id, protected_password, v4, v6, view)?;
        }
        Ok(())
    })
}

fn persist_after_password_protection<T, Protect, Persist>(
    password: &str,
    protect: Protect,
    persist: Persist,
) -> windows::core::Result<T>
where
    Protect: FnOnce(&str) -> windows::core::Result<Vec<u8>>,
    Persist: FnOnce(&[u8]) -> windows::core::Result<T>,
{
    if password.is_empty() {
        return Err(windows::core::Error::new(
            HRESULT::from(ERROR_INVALID_DATA),
            "Password must not be empty.",
        ));
    }
    let protected = protect(password)?;
    persist(&protected)
}

fn view_selection_error(error: ViewSelectionError) -> windows::core::Error {
    let message = match error {
        ViewSelectionError::InvalidAccount => "The existing registry account is invalid.",
        ViewSelectionError::Conflict => "Registry views contain conflicting account settings.",
    };
    windows::core::Error::new(HRESULT::from(ERROR_INVALID_DATA), message)
}

fn write_config_to_view(
    id: &str,
    protected_password: &[u8],
    ipv4_notify: bool,
    ipv6_notify: bool,
    view: RegistryView,
) -> windows::core::Result<()> {
    unsafe {
        let path = format!("Software\\MyDNSAdapter\\{id}");
        let subkey = HSTRING::from(&path);
        let mut hkey = HKEY::default();
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey.as_ptr()),
            0,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS | view.access_flag(),
            None,
            &mut hkey,
            None,
        )
        .ok()?;

        let result = (|| {
            set_account_key_acl(hkey)?;
            set_reg_binary(hkey, w!("Password"), protected_password)?;
            set_reg_dword(hkey, w!("IPv4Notify"), u32::from(ipv4_notify))?;
            set_reg_dword(hkey, w!("IPv6Notify"), u32::from(ipv6_notify))?;
            Ok(())
        })();
        let _ = RegCloseKey(hkey);
        result
    }
}

fn set_account_key_acl(hkey: HKEY) -> windows::core::Result<()> {
    let sddl = HSTRING::from("D:P(A;;KA;;;SY)(A;;KA;;;BA)");
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &sddl,
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }?;
    let result = unsafe {
        RegSetKeySecurity(
            hkey,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        )
    };
    unsafe {
        let _ = LocalFree(HLOCAL(descriptor.0));
    }
    result.ok()
}

pub fn protect_password(password: &str) -> windows::core::Result<Vec<u8>> {
    if password.is_empty() {
        return Err(windows::core::Error::new(
            HRESULT::from(ERROR_INVALID_DATA),
            "Password must not be empty.",
        ));
    }
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(password.len()).map_err(|_| {
            windows::core::Error::new(HRESULT::from(ERROR_INVALID_DATA), "Password is too long.")
        })?,
        pbData: password.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let protection_result = unsafe {
        CryptProtectData(
            &input,
            PCWSTR::null(),
            None,
            None,
            None,
            CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if let Err(error) = protection_result {
        if !output.pbData.is_null() {
            unsafe {
                let _ = LocalFree(HLOCAL(output.pbData as *mut _));
            }
        }
        return Err(error);
    }
    if output.pbData.is_null() || output.cbData == 0 {
        if !output.pbData.is_null() {
            unsafe {
                let _ = LocalFree(HLOCAL(output.pbData as *mut _));
            }
        }
        return Err(windows::core::Error::new(
            HRESULT::from(ERROR_INVALID_DATA),
            "DPAPI returned empty protected data.",
        ));
    }

    let mut protected =
        Vec::with_capacity(PROTECTED_PASSWORD_PREFIX.len() + output.cbData as usize);
    protected.extend_from_slice(PROTECTED_PASSWORD_PREFIX);
    protected.extend_from_slice(unsafe {
        std::slice::from_raw_parts(output.pbData, output.cbData as usize)
    });
    unsafe {
        let _ = LocalFree(HLOCAL(output.pbData as *mut _));
    }
    Ok(protected)
}

pub fn unprotect_password(protected: &[u8]) -> windows::core::Result<String> {
    if protected.len() <= PROTECTED_PASSWORD_PREFIX.len()
        || !protected.starts_with(PROTECTED_PASSWORD_PREFIX)
    {
        return Err(windows::core::Error::new(
            HRESULT::from(ERROR_INVALID_DATA),
            "Protected password data has an invalid format.",
        ));
    }
    let ciphertext = &protected[PROTECTED_PASSWORD_PREFIX.len()..];
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(ciphertext.len()).map_err(|_| {
            windows::core::Error::new(
                HRESULT::from(ERROR_INVALID_DATA),
                "Protected password data is too large.",
            )
        })?,
        pbData: ciphertext.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let unprotect_result = unsafe {
        CryptUnprotectData(
            &input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if let Err(error) = unprotect_result {
        if !output.pbData.is_null() {
            unsafe {
                let _ = LocalFree(HLOCAL(output.pbData as *mut _));
            }
        }
        return Err(error);
    }

    if output.pbData.is_null() || output.cbData == 0 {
        if !output.pbData.is_null() {
            unsafe {
                let _ = LocalFree(HLOCAL(output.pbData as *mut _));
            }
        }
        return Err(windows::core::Error::new(
            HRESULT::from(ERROR_INVALID_DATA),
            "DPAPI returned empty decrypted data.",
        ));
    }

    let plaintext = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) };
    let result = String::from_utf8(plaintext.to_vec()).map_err(|_| {
        windows::core::Error::new(
            HRESULT::from(ERROR_INVALID_DATA),
            "Decrypted password is not valid UTF-8.",
        )
    });
    unsafe {
        let _ = LocalFree(HLOCAL(output.pbData as *mut _));
    }
    result
}

/// レジストリキーにREG_SZ（文字列）型の値を設定します。
#[cfg(test)]
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

fn set_reg_binary(hkey: HKEY, name: PCWSTR, value: &[u8]) -> windows::core::Result<()> {
    unsafe { RegSetValueExW(hkey, name, 0, REG_BINARY, Some(value)).ok() }
}

/// 指定されたIDの設定をレジストリから削除します。
pub fn delete_config(id: &str) -> windows::core::Result<()> {
    let view32 = read_registry_view(RegistryView::View32)?;
    let view64 = read_registry_view(RegistryView::View64)?;
    let selected = select_write_views(id, &view32, &view64)
        .map_err(view_selection_error)?
        .ok_or_else(|| {
            windows::core::Error::new(
                HRESULT::from(ERROR_FILE_NOT_FOUND),
                "The registry account was not found.",
            )
        })?;
    for view in selected {
        unsafe {
            let mut root = HKEY::default();
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                w!("Software\\MyDNSAdapter"),
                0,
                KEY_WRITE | view.access_flag(),
                &mut root,
            )
            .ok()?;
            let subkey = HSTRING::from(id);
            let result = RegDeleteKeyExW(root, PCWSTR(subkey.as_ptr()), view.access_flag().0, 0);
            let _ = RegCloseKey(root);
            result.ok()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn config_debug_never_displays_password() {
        let config = super::Config {
            password: "fixture-do-not-disclose".into(),
            ..super::Config::default()
        };
        let output = format!("{config:?}");
        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains(&config.password));
    }

    use super::{
        Config, ConfigIssue, ConfigIssueKind, ERROR_ACCESS_DENIED, ERROR_INVALID_DATA, HRESULT,
        RegistryValue, RegistryView, RegistryViewSnapshot, ViewSelectionError, load_registry_views,
        merge_registry_views, parse_config_values, persist_after_password_protection,
        protect_password, read_config_values, read_password_value, save_to_registry,
        select_write_views, set_account_key_acl, set_reg_binary, set_reg_dword, set_reg_string,
        unprotect_password,
    };
    use std::cell::Cell;
    use std::collections::{HashMap, HashSet};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use windows::Win32::System::Registry::{
        HKEY_CURRENT_USER, KEY_ALL_ACCESS, KEY_WOW64_32KEY, KEY_WOW64_64KEY, REG_DWORD,
        REG_OPTION_NON_VOLATILE, REG_SAM_FLAGS, RegCloseKey, RegCreateKeyExW, RegDeleteKeyExW,
    };
    use windows::core::{HSTRING, PCWSTR, w};

    struct TempRegistryKey {
        handle: super::HKEY,
        path: HSTRING,
        view_flag: u32,
    }

    impl Drop for TempRegistryKey {
        fn drop(&mut self) {
            unsafe {
                let mut descriptor = super::PSECURITY_DESCRIPTOR::default();
                let restored = super::ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    &HSTRING::from("D:P(A;;KA;;;OW)(A;;KA;;;SY)(A;;KA;;;BA)"),
                    super::SDDL_REVISION_1,
                    &mut descriptor,
                    None,
                )
                .and_then(|()| {
                    super::RegSetKeySecurity(
                        self.handle,
                        super::DACL_SECURITY_INFORMATION
                            | super::PROTECTED_DACL_SECURITY_INFORMATION,
                        descriptor,
                    )
                    .ok()
                });
                if !descriptor.0.is_null() {
                    let _ = super::LocalFree(super::HLOCAL(descriptor.0));
                }
                if let Err(error) = restored {
                    eprintln!(
                        "Test-only registry key owner access restoration failed: {}",
                        error.code().0
                    );
                }
                let _ = RegCloseKey(self.handle);
                let result = RegDeleteKeyExW(
                    HKEY_CURRENT_USER,
                    PCWSTR(self.path.as_ptr()),
                    self.view_flag,
                    0,
                );
                if result.0 != 0 {
                    eprintln!("Test-only registry key cleanup failed: {}", result.0);
                }
            }
        }
    }

    fn temp_registry_key() -> TempRegistryKey {
        temp_registry_key_in_view(KEY_WOW64_64KEY)
    }

    fn temp_registry_key_in_view(view: REG_SAM_FLAGS) -> TempRegistryKey {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = HSTRING::from(format!(
            "Software\\MyDNSAdapterP1Test-{}-{}-{timestamp}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let mut handle = super::HKEY::default();
        let result = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(path.as_ptr()),
                0,
                None,
                REG_OPTION_NON_VOLATILE,
                KEY_ALL_ACCESS | view,
                None,
                &mut handle,
                None,
            )
        };
        result.ok().unwrap();
        TempRegistryKey {
            handle,
            path,
            view_flag: view.0,
        }
    }

    fn valid_config(master_id: &str) -> Config {
        Config {
            master_id: master_id.to_string(),
            password: "not-a-real-password".to_string(),
            ipv4_notify: true,
            ipv6_notify: false,
        }
    }

    fn view(configs: Vec<Config>, invalid_accounts: &[&str]) -> RegistryViewSnapshot {
        RegistryViewSnapshot {
            configs: configs
                .into_iter()
                .map(|config| (config.master_id.to_ascii_lowercase(), config))
                .collect::<HashMap<_, _>>(),
            invalid_accounts: invalid_accounts
                .iter()
                .map(|master_id| master_id.to_ascii_lowercase())
                .collect::<HashSet<_>>(),
        }
    }

    #[test]
    fn valid_registry_values_create_compatible_config() {
        let config = parse_config_values(
            "mydns-valid",
            RegistryValue::Present("secret".to_string()),
            RegistryValue::Present(1),
            RegistryValue::Present(0),
        )
        .unwrap();

        assert_eq!(config.master_id, "mydns-valid");
        assert_eq!(config.password, "secret");
        assert!(config.ipv4_notify);
        assert!(!config.ipv6_notify);
    }

    #[test]
    fn windows_registry_reader_reads_existing_value_types() {
        let key = temp_registry_key();
        set_reg_string(key.handle, w!("Password"), "test-secret").unwrap();
        set_reg_dword(key.handle, w!("IPv4Notify"), 1).unwrap();
        set_reg_dword(key.handle, w!("IPv6Notify"), 0).unwrap();

        let config = read_config_values("mydns-temp", key.handle).unwrap();
        assert_eq!(config.password, "test-secret");
        assert!(config.ipv4_notify);
        assert!(!config.ipv6_notify);
    }

    #[test]
    fn windows_registry_reader_distinguishes_missing_value() {
        let key = temp_registry_key();
        set_reg_dword(key.handle, w!("IPv4Notify"), 1).unwrap();
        set_reg_dword(key.handle, w!("IPv6Notify"), 0).unwrap();

        let issues = read_config_values("mydns-temp", key.handle).unwrap_err();
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].field, "Password");
        assert_eq!(issues[0].kind, ConfigIssueKind::MissingValue);
    }

    #[test]
    fn windows_registry_reader_distinguishes_invalid_value_type() {
        let key = temp_registry_key();
        set_reg_dword(key.handle, w!("Password"), 1).unwrap();
        set_reg_dword(key.handle, w!("IPv4Notify"), 1).unwrap();
        set_reg_dword(key.handle, w!("IPv6Notify"), 0).unwrap();

        let issues = read_config_values("mydns-temp", key.handle).unwrap_err();
        assert_eq!(issues.len(), 1);
        assert_eq!(
            issues[0].kind,
            ConfigIssueKind::InvalidType {
                expected: "REG_SZ",
                actual: REG_DWORD.0
            }
        );
    }

    #[test]
    fn dpapi_machine_scope_round_trips_without_plaintext_storage() {
        let password = "sample-secret-that-must-not-be-plain";
        let protected = protect_password(password).unwrap();

        assert!(protected.starts_with(super::PROTECTED_PASSWORD_PREFIX));
        assert!(
            !protected
                .windows(password.len())
                .any(|window| window == password.as_bytes())
        );
        assert_eq!(unprotect_password(&protected).unwrap(), password);
        assert!(protect_password("").is_err());
    }

    #[test]
    fn account_key_acl_can_be_applied_to_an_isolated_registry_key() {
        let key = temp_registry_key();
        set_account_key_acl(key.handle).unwrap();
    }

    #[test]
    fn protected_test_registry_key_is_removed_on_drop() {
        let key = temp_registry_key();
        let path = key.path.clone();
        let view = key.view_flag;
        set_account_key_acl(key.handle).unwrap();
        drop(key);
        let mut handle = super::HKEY::default();
        let result = unsafe {
            super::RegOpenKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(path.as_ptr()),
                0,
                super::KEY_READ | REG_SAM_FLAGS(view),
                &mut handle,
            )
        };
        if result.0 == 0 {
            unsafe {
                let _ = RegCloseKey(handle);
            }
        }
        assert_eq!(result, super::ERROR_FILE_NOT_FOUND);
    }

    #[test]
    fn failed_empty_password_save_does_not_touch_registry_settings() {
        assert!(save_to_registry("mydns-p2-invalid-test", "", true, true).is_err());
    }

    #[test]
    fn dpapi_failure_does_not_call_registry_persistence() {
        let persisted = Cell::new(false);
        let result = persist_after_password_protection(
            "secret",
            |_| {
                Err(windows::core::Error::new(
                    HRESULT::from(ERROR_INVALID_DATA),
                    "simulated DPAPI failure",
                ))
            },
            |_| {
                persisted.set(true);
                Ok(())
            },
        );

        assert!(result.is_err());
        assert!(!persisted.get());
    }

    #[test]
    fn dpapi_password_round_trips_from_both_registry_views() {
        let password = "machine-protected-password";
        let protected = protect_password(password).unwrap();
        let key32 = temp_registry_key_in_view(KEY_WOW64_32KEY);
        let key64 = temp_registry_key_in_view(KEY_WOW64_64KEY);
        for key in [&key32, &key64] {
            set_reg_binary(key.handle, w!("Password"), &protected).unwrap();
            set_reg_dword(key.handle, w!("IPv4Notify"), 1).unwrap();
            set_reg_dword(key.handle, w!("IPv6Notify"), 0).unwrap();
        }

        let config32 = read_config_values("mydns-dpapi", key32.handle).unwrap();
        let config64 = read_config_values("mydns-dpapi", key64.handle).unwrap();
        assert_eq!(config32.password, password);
        assert_eq!(config32, config64);
    }

    #[test]
    fn legacy_plaintext_reg_sz_remains_readable_in_both_views_without_migration() {
        let key32 = temp_registry_key_in_view(KEY_WOW64_32KEY);
        let key64 = temp_registry_key_in_view(KEY_WOW64_64KEY);
        for key in [&key32, &key64] {
            set_reg_string(key.handle, w!("Password"), "legacy-plain-secret").unwrap();
            set_reg_dword(key.handle, w!("IPv4Notify"), 1).unwrap();
            set_reg_dword(key.handle, w!("IPv6Notify"), 0).unwrap();
        }

        assert_eq!(
            read_config_values("mydns-legacy", key32.handle)
                .unwrap()
                .password,
            "legacy-plain-secret"
        );
        assert_eq!(
            read_config_values("mydns-legacy", key64.handle)
                .unwrap()
                .password,
            "legacy-plain-secret"
        );
        assert_eq!(
            unsafe { read_password_value(key32.handle, "Password") },
            RegistryValue::Present("legacy-plain-secret".to_string())
        );
        assert_eq!(
            unsafe { read_password_value(key64.handle, "Password") },
            RegistryValue::Present("legacy-plain-secret".to_string())
        );
    }

    #[test]
    fn corrupt_dpapi_blob_is_not_treated_as_an_empty_password() {
        let key = temp_registry_key();
        let mut protected = protect_password("secret").unwrap();
        let last = protected.len() - 1;
        protected[last] ^= 0x80;
        set_reg_binary(key.handle, w!("Password"), &protected).unwrap();
        set_reg_dword(key.handle, w!("IPv4Notify"), 1).unwrap();
        set_reg_dword(key.handle, w!("IPv6Notify"), 0).unwrap();

        let issues = read_config_values("mydns-dpapi-corrupt", key.handle).unwrap_err();
        assert_eq!(issues.len(), 1);
        assert!(matches!(
            issues[0].kind,
            ConfigIssueKind::DecryptionError(_)
        ));
        assert!(unprotect_password(&protected).is_err());
    }

    #[test]
    fn missing_values_are_distinguished_from_present_defaults() {
        let issues = parse_config_values(
            "mydns-missing",
            RegistryValue::Missing,
            RegistryValue::Missing,
            RegistryValue::Present(0),
        )
        .unwrap_err();

        assert_eq!(issues.len(), 2);
        assert!(issues.iter().any(|issue| {
            issue.field == "Password" && issue.kind == ConfigIssueKind::MissingValue
        }));
        assert!(issues.iter().any(|issue| {
            issue.field == "IPv4Notify" && issue.kind == ConfigIssueKind::MissingValue
        }));
    }

    #[test]
    fn invalid_registry_type_is_reported_with_expected_type() {
        let issues = parse_config_values(
            "mydns-wrong-type",
            RegistryValue::Present("secret".to_string()),
            RegistryValue::InvalidType(1),
            RegistryValue::Present(0),
        )
        .unwrap_err();

        assert_eq!(
            issues[0].kind,
            ConfigIssueKind::InvalidType {
                expected: "REG_DWORD",
                actual: 1
            }
        );
    }

    #[test]
    fn registry_access_denied_is_preserved_as_api_error() {
        let issues = parse_config_values(
            "mydns-denied",
            RegistryValue::Present("secret".to_string()),
            RegistryValue::ApiError(5),
            RegistryValue::Present(0),
        )
        .unwrap_err();

        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].kind, ConfigIssueKind::ApiError(5));
    }

    #[test]
    fn account_access_denied_is_not_classified_as_corrupt_data() {
        let access_denied = ConfigIssue {
            master_id: "mydns-protected".to_string(),
            field: "Password",
            kind: ConfigIssueKind::ApiError(ERROR_ACCESS_DENIED.0),
        };
        let invalid_type = ConfigIssue {
            master_id: "mydns-corrupt".to_string(),
            field: "Password",
            kind: ConfigIssueKind::InvalidType {
                expected: "REG_SZ",
                actual: 4,
            },
        };

        assert!(super::is_access_denied_issue(&access_denied));
        assert!(!super::is_access_denied_issue(&invalid_type));
    }

    #[test]
    fn one_corrupt_account_does_not_hide_other_valid_accounts() {
        let merged = merge_registry_views(
            view(vec![valid_config("mydns-good")], &["mydns-corrupt"]),
            view(
                vec![valid_config("mydns-good"), valid_config("mydns-corrupt")],
                &[],
            ),
        );

        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].master_id, "mydns-good");
    }

    #[test]
    fn identical_accounts_in_both_views_are_returned_once() {
        let merged = merge_registry_views(
            view(vec![valid_config("mydns-same")], &[]),
            view(vec![valid_config("mydns-same")], &[]),
        );

        assert_eq!(merged.len(), 1);
    }

    #[test]
    fn conflicting_accounts_in_both_views_are_not_selected() {
        let config32 = valid_config("mydns-conflict");
        let mut config64 = config32.clone();
        config64.password = "different-secret".to_string();
        let merged = merge_registry_views(view(vec![config32], &[]), view(vec![config64], &[]));

        assert!(merged.is_empty());
    }

    #[test]
    fn new_account_defaults_to_explicit_64_bit_view_policy() {
        assert_eq!(
            select_write_views("mydns-new", &view(vec![], &[]), &view(vec![], &[])),
            Ok(None)
        );
    }

    #[test]
    fn existing_account_stays_in_its_original_view() {
        let config = valid_config("mydns-legacy");
        assert_eq!(
            select_write_views(
                "mydns-legacy",
                &view(vec![config.clone()], &[]),
                &view(vec![], &[])
            ),
            Ok(Some(vec![RegistryView::View32]))
        );
        assert_eq!(
            select_write_views("mydns-legacy", &view(vec![], &[]), &view(vec![config], &[])),
            Ok(Some(vec![RegistryView::View64]))
        );
    }

    #[test]
    fn same_existing_account_in_both_views_updates_both() {
        let config = valid_config("mydns-mirrored");
        assert_eq!(
            select_write_views(
                "mydns-mirrored",
                &view(vec![config.clone()], &[]),
                &view(vec![config], &[])
            ),
            Ok(Some(vec![RegistryView::View32, RegistryView::View64]))
        );
    }

    #[test]
    fn conflicting_or_invalid_view_never_selects_a_write_target() {
        let config32 = valid_config("mydns-conflict");
        let mut config64 = config32.clone();
        config64.ipv6_notify = true;
        assert_eq!(
            select_write_views(
                "mydns-conflict",
                &view(vec![config32], &[]),
                &view(vec![config64], &[])
            ),
            Err(ViewSelectionError::Conflict)
        );
        assert_eq!(
            select_write_views(
                "mydns-invalid",
                &view(vec![], &["mydns-invalid"]),
                &view(vec![valid_config("mydns-invalid")], &[])
            ),
            Err(ViewSelectionError::InvalidAccount)
        );
    }

    #[test]
    fn whole_view_access_error_is_not_converted_to_empty_configuration() {
        let result = load_registry_views(
            || {
                Err(windows::core::Error::from_hresult(HRESULT::from(
                    ERROR_ACCESS_DENIED,
                )))
            },
            || Ok(RegistryViewSnapshot::default()),
        );

        assert_eq!(
            result.unwrap_err().code(),
            HRESULT::from(ERROR_ACCESS_DENIED)
        );
    }

    #[test]
    fn missing_roots_in_both_views_are_an_empty_configuration() {
        let result = load_registry_views(
            || Ok(RegistryViewSnapshot::default()),
            || Ok(RegistryViewSnapshot::default()),
        );

        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn all_invalid_or_conflicting_accounts_are_not_reported_as_missing() {
        let invalid = load_registry_views(
            || Ok(view(vec![], &["mydns-invalid"])),
            || Ok(view(vec![], &[])),
        )
        .unwrap_err();
        assert_eq!(invalid.code(), HRESULT::from(ERROR_INVALID_DATA));
        let original = valid_config("mydns-conflict");
        let mut changed = original.clone();
        changed.password = "different-fixture".into();
        let conflict = load_registry_views(
            || Ok(view(vec![original], &[])),
            || Ok(view(vec![changed], &[])),
        )
        .unwrap_err();
        assert_eq!(conflict.code(), HRESULT::from(ERROR_INVALID_DATA));
        let usable = load_registry_views(
            || Ok(view(vec![], &["mydns-invalid"])),
            || Ok(view(vec![valid_config("mydns-valid")], &[])),
        )
        .unwrap();
        assert_eq!(usable.len(), 1);
        assert_eq!(usable[0].master_id, "mydns-valid");
    }
}

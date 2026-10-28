#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// 阿信电脑同步器桌面端（Tauri 2）— S1 切片
//
// 边界：这里只做 WebView 做不到或不该做的事 —— 机器码、令牌落盘、HTTP（绕开
// WebView 的 CORS 限制）、审计日志。授权判定全部留给远程后台，本地不做到期判断。

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// 生产授权后台；本地联调可用 HZ_API_BASE 覆盖（与 license_client.py 同名变量）。
const API_BASE_DEFAULT: &str = "http://192.168.3.123:3010";

/// 令牌文件签名密钥，与 license_client.py 的 SECRET 保持一致 ——
/// 改这里等于让所有老用户的 account.json 失效（会退回登录门）。
const TOKEN_SECRET: &[u8] = b"HzWindowSyncer@2026#license-sign";

fn api_base() -> String {
    std::env::var("HZ_API_BASE").unwrap_or_else(|_| API_BASE_DEFAULT.to_string())
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn state_dir() -> PathBuf {
    let base = std::env::var("APPDATA").unwrap_or_else(|_| {
        std::env::var("USERPROFILE").unwrap_or_else(|_| ".".to_string())
    });
    let dir = PathBuf::from(base).join("HzWindowSyncer");
    let _ = fs::create_dir_all(&dir);
    dir
}

fn token_path() -> PathBuf {
    state_dir().join("account.json")
}

/// 机器码：注册表 MachineGuid + 计算机名 的 SHA256 前 16 位（大写）。
/// 与 license_client.py:machine_code 逐字节一致，否则老用户会被判成"换机"。
#[tauri::command]
fn machine_code() -> String {
    let guid = read_machine_guid().unwrap_or_else(|| "unknown-guid".to_string());
    let name = std::env::var("COMPUTERNAME").unwrap_or_default();
    let raw = format!("{}|{}", guid, name);
    let digest = Sha256::digest(raw.as_bytes());
    hex::encode_upper(digest)[..16].to_string()
}

fn read_machine_guid() -> Option<String> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm
        .open_subkey_with_flags("SOFTWARE\\Microsoft\\Cryptography", KEY_READ)
        .ok()?;
    key.get_value::<String, _>("MachineGuid").ok()
}

fn json_str(v: &str) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "\"\"".to_string())
}

/// Python 侧用 json.dumps(..., sort_keys=True) 生成待签串，默认分隔符是 ", " 和 ": "。
/// 这里手工拼同一格式，保证老令牌的签名校验能通过。
fn token_body(expires_at: i64, machine: &str, saved_at: i64, token: &str, user: &str) -> String {
    format!(
        "{{\"expires_at\": {}, \"machine\": {}, \"saved_at\": {}, \"token\": {}, \"user\": {}}}",
        expires_at,
        json_str(machine),
        saved_at,
        json_str(token),
        json_str(user)
    )
}

fn sign(body: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(TOKEN_SECRET).expect("hmac key");
    mac.update(body.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[tauri::command]
fn save_token(token: String, user: String, expires_at: i64) -> Result<(), String> {
    let machine = machine_code();
    let saved_at = now_secs();
    let body = token_body(expires_at, &machine, saved_at, &token, &user);
    let sig = sign(&body);
    let data = json!({
        "token": token,
        "user": user,
        "machine": machine,
        "expires_at": expires_at,
        "saved_at": saved_at,
        "sig": sig,
    });
    let path = token_path();
    let tmp = path.with_extension("json.tmp");
    let text = serde_json::to_string(&data).map_err(|e| e.to_string())?;
    fs::write(&tmp, text).map_err(|e| e.to_string())?;
    fs::rename(&tmp, &path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        e.to_string()
    })
}

#[tauri::command]
fn load_token() -> Option<Value> {
    let text = fs::read_to_string(token_path()).ok()?;
    let data: Value = serde_json::from_str(&text).ok()?;
    let token = data.get("token")?.as_str()?.to_string();
    let user = data.get("user")?.as_str()?.to_string();
    let machine = data.get("machine")?.as_str()?.to_string();
    let expires_at = data.get("expires_at")?.as_i64()?;
    let saved_at = data.get("saved_at")?.as_i64()?;
    let sig = data.get("sig")?.as_str()?.to_string();
    if machine != machine_code() {
        return None;
    }
    let expect = sign(&token_body(expires_at, &machine, saved_at, &token, &user));
    if expect != sig {
        return None;
    }
    Some(json!({
        "token": token,
        "user": user,
        "machine": machine,
        "expires_at": expires_at,
        "saved_at": saved_at,
    }))
}

#[tauri::command]
fn clear_token() {
    let _ = fs::remove_file(token_path());
}

/// 账号域 HTTP。放在 Rust 侧的理由：WebView 的 Origin 是 tauri://localhost，
/// 跨源到 .123:3010 会被 CORS 拦掉；这里用原生客户端，服务端无需为桌面壳开口子。
#[tauri::command]
async fn api_post(path: String, body: Value) -> Result<Value, String> {
    let url = format!("{}{}", api_base(), path);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status();
    let text = resp.text().await.map_err(|e| e.to_string())?;
    // 与 Python 版一致：HTTP 4xx 只要响应体是 JSON 就按业务结果返回
    serde_json::from_str::<Value>(&text).map_err(|_| format!("HTTP {}", status.as_u16()))
}

#[tauri::command]
async fn api_base_url() -> String {
    api_base()
}

fn local_stamp() -> String {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::Foundation::SYSTEMTIME;
        use windows_sys::Win32::System::SystemInformation::GetLocalTime;
        let mut st: SYSTEMTIME = std::mem::zeroed();
        GetLocalTime(&mut st);
        return format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond
        );
    }
    #[cfg(not(windows))]
    {
        format!("{}", now_secs())
    }
}

/// 审计日志：写在 exe 同目录 audit.log，格式与 Python 版一致
/// （`2026-10-28 18:29:58 [LOGIN] 账号登录 xxx`），现有排查习惯不用改。
#[tauri::command]
fn audit_write(kind: String, msg: String) -> Result<(), String> {
    let dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    let line = format!("{} [{}] {}\n", local_stamp(), kind, msg);
    use std::io::Write;
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("audit.log"))
        .map_err(|e| e.to_string())?;
    f.write_all(line.as_bytes()).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 待签串必须与 license_client.py 的 json.dumps(sort_keys=True) 逐字节一致，
    /// 否则老用户的 account.json 会验签失败，被当成未登录。
    #[test]
    fn token_body_matches_python() {
        let body = token_body(1764239999, "ABCDEF0123456789", 1764240000, "deadbeef", "s1uitest");
        assert_eq!(
            body,
            "{\"expires_at\": 1764239999, \"machine\": \"ABCDEF0123456789\", \"saved_at\": 1764240000, \"token\": \"deadbeef\", \"user\": \"s1uitest\"}"
        );
        // 期望值由 Python hmac.new(SECRET, body, sha256).hexdigest() 算出
        assert_eq!(
            sign(&body),
            "027bba3b6b4ecb7f5ad4e39daae83e69c66ddd1f15b81cb1f9c7be50379cae72"
        );
    }

    #[test]
    fn machine_code_shape() {
        let m = machine_code();
        assert_eq!(m.len(), 16);
        assert!(m.chars().all(|c| c.is_ascii_digit() || ('A'..='F').contains(&c)));
    }
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            machine_code,
            save_token,
            load_token,
            clear_token,
            api_post,
            api_base_url,
            audit_write
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

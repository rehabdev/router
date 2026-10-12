use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Mutex,
};

use asira_tunnel::{connect_client, ClientConfig, ClientSession};
use serde::{Deserialize, Serialize};
use tauri::Manager;

const SETTINGS_FILE: &str = "settings.json";
const PASSPHRASE_FILE: &str = "passphrase.dpapi";
const DEFAULT_PORT: u16 = 4433;

#[derive(Default)]
struct AppState {
    session: Mutex<Option<ClientSession>>,
    settings: Mutex<()>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct StoredSettings {
    server: String,
    port: u16,
    routes: String,
}

#[derive(Debug, Serialize)]
struct SettingsResponse {
    server: String,
    port: u16,
    routes: String,
    passphrase: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum WindowControl {
    Minimize,
    Close,
}

#[tauri::command]
fn load_settings(app: tauri::AppHandle) -> Result<SettingsResponse, String> {
    let directory = settings_directory(&app)?;
    let stored = match fs::read(directory.join(SETTINGS_FILE)) {
        Ok(bytes) => serde_json::from_slice::<StoredSettings>(&bytes)
            .map_err(|error| format!("reading saved settings: {error}"))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => StoredSettings {
            port: DEFAULT_PORT,
            ..StoredSettings::default()
        },
        Err(error) => return Err(format!("reading saved settings: {error}")),
    };
    let passphrase = match fs::read(directory.join(PASSPHRASE_FILE)) {
        Ok(bytes) => Some(unprotect_passphrase(&bytes)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(format!("reading saved passphrase: {error}")),
    };
    Ok(SettingsResponse {
        server: stored.server,
        port: if stored.port == 0 {
            DEFAULT_PORT
        } else {
            stored.port
        },
        routes: stored.routes,
        passphrase,
    })
}

#[tauri::command]
fn save_settings(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    server: String,
    port: u16,
    passphrase: String,
    routes: String,
) -> Result<(), String> {
    let _settings_guard = state
        .settings
        .lock()
        .map_err(|_| "settings state is unavailable".to_owned())?;
    let directory = settings_directory(&app)?;
    fs::create_dir_all(&directory)
        .map_err(|error| format!("creating app settings folder: {error}"))?;
    let stored = StoredSettings {
        server,
        port,
        routes,
    };
    let settings_json = serde_json::to_vec_pretty(&stored)
        .map_err(|error| format!("encoding saved settings: {error}"))?;
    write_settings_file(&directory.join(SETTINGS_FILE), &settings_json)?;

    let passphrase_path = directory.join(PASSPHRASE_FILE);
    if passphrase.is_empty() {
        match fs::remove_file(passphrase_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("removing saved passphrase: {error}")),
        }
    } else {
        let protected = protect_passphrase(&passphrase)?;
        write_settings_file(&passphrase_path, &protected)?;
    }
    Ok(())
}

#[tauri::command]
async fn window_control(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    control: WindowControl,
) -> Result<(), String> {
    let window = app
        .get_webview_window("main")
        .ok_or_else(|| "main window is unavailable".to_owned())?;

    match control {
        WindowControl::Minimize => window.minimize().map_err(|error| error.to_string()),
        WindowControl::Close => {
            let session = state
                .session
                .lock()
                .map_err(|_| "client state is unavailable".to_owned())?
                .take();
            let cleanup_result = if let Some(session) = session {
                session
                    .disconnect()
                    .await
                    .map_err(|error| error.to_string())
            } else {
                Ok(())
            };
            app.exit(0);
            cleanup_result
        }
    }
}

#[tauri::command]
async fn connect(
    state: tauri::State<'_, AppState>,
    server: String,
    port: u16,
    passphrase: String,
    routes: String,
) -> Result<String, String> {
    let ip: Ipv4Addr = server
        .parse()
        .map_err(|_| "enter a valid IPv4 VPS address".to_owned())?;
    let config =
        ClientConfig::from_route_text(SocketAddr::new(IpAddr::V4(ip), port), passphrase, &routes)
            .map_err(|error| error.to_string())?;
    {
        let current = state
            .session
            .lock()
            .map_err(|_| "client state is unavailable".to_owned())?;
        if current.is_some() {
            return Err("a tunnel is already connected".to_owned());
        }
    }
    let session = connect_client(config)
        .await
        .map_err(|error| error.to_string())?;
    let assigned = session.status.assigned_ipv4.to_string();
    let rejected_session = {
        let mut current = state
            .session
            .lock()
            .map_err(|_| "client state is unavailable".to_owned())?;
        if current.is_some() {
            Some(session)
        } else {
            *current = Some(session);
            None
        }
    };
    if let Some(session) = rejected_session {
        if let Err(error) = session.disconnect().await {
            return Err(format!(
                "a tunnel is already connected; cleanup of the second connection failed: {error}"
            ));
        }
        return Err("a tunnel is already connected".to_owned());
    }
    Ok(assigned)
}

#[tauri::command]
async fn disconnect(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let session = state
        .session
        .lock()
        .map_err(|_| "client state is unavailable".to_owned())?
        .take();
    if let Some(session) = session {
        session
            .disconnect()
            .await
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            connect,
            disconnect,
            load_settings,
            save_settings,
            window_control
        ])
        .run(tauri::generate_context!())
        .expect("error while running Asira Router");
}

fn settings_directory(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map_err(|error| format!("locating app settings folder: {error}"))
}

fn write_settings_file(path: &Path, contents: &[u8]) -> Result<(), String> {
    let temporary_path = path.with_extension(format!(
        "{}{}.tmp",
        path.extension()
            .and_then(|value| value.to_str())
            .unwrap_or(""),
        std::process::id()
    ));
    fs::write(&temporary_path, contents)
        .map_err(|error| format!("writing {}: {error}", path.display()))?;
    if let Err(error) = fs::rename(&temporary_path, path) {
        let _ = fs::remove_file(&temporary_path);
        return Err(format!("replacing {}: {error}", path.display()));
    }
    Ok(())
}

#[cfg(windows)]
fn protect_passphrase(passphrase: &str) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB},
    };

    let input_bytes = passphrase.as_bytes();
    let input = CRYPT_INTEGER_BLOB {
        cbData: input_bytes
            .len()
            .try_into()
            .map_err(|_| "passphrase is too large to save".to_owned())?,
        pbData: input_bytes.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let success = unsafe {
        CryptProtectData(
            &input,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if success == 0 {
        return Err(format!(
            "Windows could not protect the passphrase: {}",
            std::io::Error::last_os_error()
        ));
    }
    if output.pbData.is_null() {
        return Err("Windows returned an empty protected passphrase".to_owned());
    }
    let protected =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData.cast());
    }
    Ok(protected)
}

#[cfg(not(windows))]
fn protect_passphrase(_passphrase: &str) -> Result<Vec<u8>, String> {
    Err("protected settings are only supported on Windows".to_owned())
}

#[cfg(windows)]
fn unprotect_passphrase(protected: &[u8]) -> Result<String, String> {
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
        },
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: protected
            .len()
            .try_into()
            .map_err(|_| "saved passphrase is too large".to_owned())?,
        pbData: protected.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let success = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if success == 0 {
        return Err(format!(
            "Windows could not unlock the saved passphrase: {}",
            std::io::Error::last_os_error()
        ));
    }
    if output.pbData.is_null() {
        return Err("Windows returned an empty saved passphrase".to_owned());
    }
    let bytes = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) };
    let passphrase = String::from_utf8(bytes.to_vec())
        .map_err(|_| "saved passphrase is not valid UTF-8".to_owned());
    unsafe {
        LocalFree(output.pbData.cast());
    }
    passphrase
}

#[cfg(not(windows))]
fn unprotect_passphrase(_protected: &[u8]) -> Result<String, String> {
    Err("protected settings are only supported on Windows".to_owned())
}

#[cfg(all(test, windows))]
mod settings_tests {
    use super::{protect_passphrase, unprotect_passphrase};

    #[test]
    fn dpapi_round_trip() {
        let original = "a-long-test-passphrase-for-asira-router";
        let protected = protect_passphrase(original).expect("protecting test passphrase");
        assert_ne!(protected, original.as_bytes());
        assert_eq!(
            unprotect_passphrase(&protected).expect("unprotecting test passphrase"),
            original
        );
    }
}

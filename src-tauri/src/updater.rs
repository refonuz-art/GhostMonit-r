//! Self-update from GitHub Releases. Every package is verified against the public key
//! in tauri.conf.json (minisign) before it runs; an unsigned or tampered installer is
//! rejected. Installing always needs the user's click — we only notify automatically.

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tauri::{AppHandle, Emitter};
use tauri_plugin_notification::NotificationExt;
use tauri_plugin_updater::UpdaterExt;

use crate::state::Shared;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    pub current: String,
    pub version: String,
    pub notes: Option<String>,
    pub date: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Progress {
    downloaded: u64,
    total: Option<u64>,
}

fn friendly(e: impl std::fmt::Display) -> String {
    let m = e.to_string();
    if m.contains("signature") {
        format!("Güncelleme imzası doğrulanamadı, kurulmadı: {m}")
    } else if m.contains("404") || m.contains("Could not fetch") {
        "Yayımlanmış bir sürüm bulunamadı".into()
    } else {
        format!("Güncelleme denetlenemedi: {m}")
    }
}

pub async fn check(app: &AppHandle) -> Result<Option<UpdateInfo>, String> {
    let u = app.updater().map_err(friendly)?.check().await.map_err(friendly)?;
    Ok(u.map(|u| UpdateInfo {
        current: u.current_version.clone(),
        version: u.version.clone(),
        notes: u.body.clone(),
        date: u.date.map(|d| d.to_string()),
    }))
}

#[tauri::command]
pub async fn check_update(app: AppHandle) -> Result<Option<UpdateInfo>, String> {
    check(&app).await
}

#[tauri::command]
pub async fn install_update(app: AppHandle) -> Result<(), String> {
    let u = app
        .updater()
        .map_err(friendly)?
        .check()
        .await
        .map_err(friendly)?
        .ok_or("Kurulacak yeni sürüm yok")?;
    let mut downloaded = 0u64;
    let a = app.clone();
    u.download_and_install(
        move |chunk, total| {
            downloaded += chunk as u64;
            let _ = a.emit("gm://update-progress", Progress { downloaded, total });
        },
        || {},
    )
    .await
    .map_err(friendly)?;
    // On Windows the installer takes over and closes us; restart covers the other case.
    app.restart();
}

/// Check shortly after start, then twice a day. Notify once per new version.
pub fn spawn(app: AppHandle, shared: Arc<Shared>) {
    tauri::async_runtime::spawn(async move {
        tokio_sleep(Duration::from_secs(90)).await;
        loop {
            if shared.settings.read().update_check {
                if let Ok(Some(info)) = check(&app).await {
                    let _ = app.emit("gm://update", &info);
                    let seen = shared.store.lock().setting("update_notified").ok().flatten();
                    if seen.as_deref() != Some(info.version.as_str()) {
                        let _ = shared.store.lock().set_setting("update_notified", &info.version);
                        let _ = app
                            .notification()
                            .builder()
                            .title(format!("Ghost Monitor {} hazır", info.version))
                            .body("Yeni sürümü Ayarlar → Güncelleme bölümünden kurabilirsiniz.")
                            .show();
                    }
                }
            }
            tokio_sleep(Duration::from_secs(12 * 3600)).await;
        }
    });
}

async fn tokio_sleep(d: Duration) {
    let _ = tauri::async_runtime::spawn_blocking(move || std::thread::sleep(d)).await;
}

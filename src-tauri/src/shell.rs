//! Desktop integration: tray icon, close-to-tray, single window, toast notifications.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, WindowEvent};
use tauri_plugin_notification::NotificationExt;

use crate::model::{SecurityEvent, Severity};
use crate::state::Shared;

const TRAY_ID: &str = "main";
/// At most one toast per window; the rest are summarised in the next one.
const NOTIFY_GAP: Duration = Duration::from_secs(20);

#[derive(Default)]
pub struct NotifyState {
    last: Option<Instant>,
    held: u32,
}

pub fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
    if let Some(s) = app.try_state::<std::sync::Arc<Shared>>() {
        s.background.store(false, Ordering::Relaxed);
    }
}

pub fn install_tray(app: &AppHandle) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Ghost Monitor'ü aç", true, None::<&str>)?;
    let scan = MenuItem::with_id(app, "scan", "Açılış girdilerini şimdi tara", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Çıkış (izlemeyi durdur)", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &scan, &PredefinedMenuItem::separator(app)?, &quit])?;

    let mut b = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip("Ghost Monitor · izleniyor")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, e| match e.id.as_ref() {
            "open" => show_main(app),
            "scan" => {
                if let Some(s) = app.try_state::<std::sync::Arc<Shared>>() {
                    if let Some(tx) = s.startup_rescan.lock().as_ref() {
                        let _ = tx.send(());
                    }
                }
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, e| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = e {
                show_main(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        b = b.icon(icon.clone());
    }
    b.build(app)?;
    Ok(())
}

/// Tooltip reflects the open findings so the tray alone tells you if something is wrong.
pub fn update_tray(app: &AppHandle, open: usize, top: Option<Severity>) {
    let Some(tray) = app.tray_by_id(TRAY_ID) else { return };
    let text = match top {
        None => "Ghost Monitor · temiz".to_string(),
        Some(s) => format!("Ghost Monitor · {open} bulgu (en yüksek: {})", severity_tr(s)),
    };
    let _ = tray.set_tooltip(Some(text));
}

/// Window close → hide to tray when enabled.
pub fn on_window_event(window: &tauri::Window, event: &WindowEvent) {
    if let WindowEvent::CloseRequested { api, .. } = event {
        let app = window.app_handle();
        let Some(s) = app.try_state::<std::sync::Arc<Shared>>() else { return };
        if !s.settings.read().close_to_tray {
            return;
        }
        api.prevent_close();
        let _ = window.hide();
        s.background.store(true, Ordering::Relaxed);
        let st = s.store.lock();
        if st.setting("tray_hint_shown").ok().flatten().is_none() {
            let _ = st.set_setting("tray_hint_shown", "1");
            drop(st);
            toast(
                app,
                "Ghost Monitor arka planda çalışıyor",
                "İzleme sürüyor. Pencereyi tepsi simgesinden açabilir, tamamen kapatmak için sağ tıklayıp Çıkış'ı seçebilirsiniz.",
            );
        }
    }
}

fn toast(app: &AppHandle, title: &str, body: &str) {
    let _ = app.notification().builder().title(title).body(body).show();
}

pub fn severity_tr(s: Severity) -> &'static str {
    match s {
        Severity::Info => "bilgi",
        Severity::Low => "düşük",
        Severity::Medium => "orta",
        Severity::High => "yüksek",
        Severity::Critical => "kritik",
    }
}

/// Decide whether an event becomes a Windows notification. Pure, so it is testable.
pub fn should_notify(
    st: &mut NotifyState,
    sev: Severity,
    min: Severity,
    enabled: bool,
    window_focused: bool,
    now: Instant,
) -> Option<u32> {
    if !enabled || sev < min || sev == Severity::Info {
        return None;
    }
    if window_focused {
        return None; // already on screen in the timeline
    }
    if st.last.is_some_and(|t| now.duration_since(t) < NOTIFY_GAP) {
        st.held += 1;
        return None;
    }
    st.last = Some(now);
    let held = std::mem::take(&mut st.held);
    Some(held)
}

pub fn maybe_notify(app: &AppHandle, shared: &Shared, e: &SecurityEvent) {
    let (enabled, min) = {
        let s = shared.settings.read();
        (s.notify, s.notify_min_severity)
    };
    let focused = app
        .get_webview_window("main")
        .map(|w| w.is_visible().unwrap_or(false) && w.is_focused().unwrap_or(false))
        .unwrap_or(false);
    let held = should_notify(&mut shared.notifier.lock(), e.severity, min, enabled, focused, Instant::now());
    let Some(held) = held else { return };
    let mut body = e.detail.chars().take(180).collect::<String>();
    if held > 0 {
        body.push_str(&format!("\n(+{held} olay daha — uygulamada görün)"));
    }
    toast(app, &format!("[{}] {}", severity_tr(e.severity).to_uppercase(), e.title), &body);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notifications_respect_threshold_focus_and_rate() {
        let mut st = NotifyState::default();
        let t = Instant::now();
        let m = Severity::Medium;
        assert_eq!(should_notify(&mut st, Severity::Low, m, true, false, t), None, "below threshold");
        assert_eq!(should_notify(&mut st, Severity::High, m, false, false, t), None, "disabled");
        assert_eq!(should_notify(&mut st, Severity::High, m, true, true, t), None, "window focused");
        assert_eq!(should_notify(&mut st, Severity::High, m, true, false, t), Some(0));
        assert_eq!(should_notify(&mut st, Severity::High, m, true, false, t + Duration::from_secs(5)), None);
        assert_eq!(should_notify(&mut st, Severity::Critical, m, true, false, t + Duration::from_secs(6)), None);
        assert_eq!(should_notify(&mut st, Severity::Medium, m, true, false, t + Duration::from_secs(25)), Some(2));
    }
}

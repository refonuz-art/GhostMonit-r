mod assistant;
mod collectors;
mod commands;
mod commands_intel;
mod commands_guard;
mod commands_assistant;
mod engine;
mod guard;
mod intel;
mod model;
mod monitor;
mod report;
mod settings;
mod shell;
mod startup_scan;
mod updater;
mod watchers;
mod sigcache;
mod state;
mod store;
mod winapi;

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};
use sysinfo::System;
use tauri::Manager;

use crate::state::Shared;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Called by the uninstaller: remove the ransomware decoys we planted, then exit.
    if std::env::args().any(|a| a == "--cleanup") {
        guard::canary::remove_all();
        return;
    }
    winapi::elevation::wait_for_predecessor();
    tauri::Builder::default()
        // Must be first: a second launch (e.g. shortcut while autostarted in tray) focuses us.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| shell::show_main(app)))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .on_window_event(shell::on_window_event)
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&data_dir)?;
            let store = store::Store::open(&data_dir.join("ghost.db"))?;
            let app_settings = settings::AppSettings::load(&store);

            let mut sys = System::new()?;
            sys.refresh_cpu_all();
            sys.refresh_memory();
            let elevated = winapi::elevation::is_elevated();
            let host = collectors::system::host_info(&sys, elevated, &data_dir.to_string_lossy());

            let shared = Arc::new(Shared {
                host: RwLock::new(host),
                metrics: RwLock::new(None),
                processes: RwLock::new(Vec::new()),
                connections: RwLock::new(Vec::new()),
                findings: RwLock::new(Vec::new()),
                store: Mutex::new(store),
                sigs: sigcache::SigCache::new(),
                rdns: intel::dns::ReverseDns::new(),
                geo: intel::geo::Geo::new(&data_dir),
                exe_hashes: intel::hashdb::ExeHashes::new(),
                startup: RwLock::new(Vec::new()),
                startup_findings: RwLock::new(Vec::new()),
                startup_scanned_at: RwLock::new(None),
                startup_rescan: Mutex::new(None),
                background: AtomicBool::new(false),
                settings: RwLock::new(app_settings),
                notifier: Mutex::new(shell::NotifyState::default()),
                watch_findings: RwLock::new(Vec::new()),
                auto_scans: RwLock::new(Vec::new()),
                drives: RwLock::new(Vec::new()),
                guard: RwLock::new(guard::GuardState::default()),
                net_usage: RwLock::new(guard::netstats::NetUsage::default()),
            });
            app.manage(shared.clone());
            let tx = startup_scan::spawn(app.handle().clone(), shared.clone());
            *shared.startup_rescan.lock() = Some(tx);
            watchers::spawn(app.handle().clone(), shared.clone());
            guard::spawn(app.handle().clone(), shared.clone());
            updater::spawn(app.handle().clone(), shared.clone());
            monitor::spawn(app.handle().clone(), shared.clone());
            shell::install_tray(app.handle())?;
            // Autostart launches with --hidden: monitor from the tray, no window flash.
            let hidden = std::env::args().any(|a| a == settings::HIDDEN_ARG);
            if hidden {
                shared.background.store(true, std::sync::atomic::Ordering::Relaxed);
            } else if let Some(w) = app.get_webview_window("main") {
                w.show()?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_snapshot,
            commands::get_events,
            commands::get_finding_history,
            commands::kill_process,
            commands::set_trust,
            commands::set_finding_status,
            commands::set_background,
            commands::relaunch_admin,
            commands::reveal_in_explorer,
            commands::geo_status,
            commands::download_geo,
            commands::conn_history,
            commands_intel::analyze_file,
            commands_intel::hashdb_stats,
            commands_intel::hashdb_import,
            commands_intel::hashdb_clear,
            commands_intel::vt_has_key,
            commands_intel::vt_set_key,
            commands_intel::vt_lookup,
            commands_intel::startup_items,
            commands_intel::rescan_startup,
            commands_intel::ip_info,
            commands_intel::build_report,
            commands_intel::export_report,
            commands::get_settings,
            commands::save_settings,
            commands::quit_app,
            commands_intel::auto_scans,
            commands_intel::drives,
            commands_intel::abuse_has_key,
            commands_intel::abuse_set_key,
            commands_intel::feed_update_now,
            updater::check_update,
            updater::install_update,
            commands_guard::guard_state,
            commands_guard::guard_refresh,
            commands_guard::fw_rules,
            commands_guard::fw_block,
            commands_guard::fw_unblock,
            commands_guard::quarantine_list,
            commands_guard::quarantine_add,
            commands_guard::quarantine_restore,
            commands_guard::quarantine_delete,
            commands_guard::remote_status,
            commands_guard::remote_set_telegram,
            commands_guard::remote_set_discord,
            commands_guard::remote_test,
            commands_guard::lan_sweep,
            commands_guard::net_usage,
            commands_guard::suspend_process,
            commands_assistant::assistant_status,
            commands_assistant::assistant_set_azure,
            commands_assistant::assistant_set_claude,
            commands_assistant::assistant_tts,
            commands_assistant::assistant_stt,
            commands_assistant::assistant_find_app,
            commands_assistant::assistant_launch,
            commands_assistant::assistant_open_url,
            commands_assistant::assistant_weather,
            commands_assistant::assistant_ask,
            commands_assistant::assistant_install_stt,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Ghost Monitor");
}

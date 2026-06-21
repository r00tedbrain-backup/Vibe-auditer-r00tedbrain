mod commands;
mod db;
mod engine;

#[cfg(test)]
mod smoke;

use std::sync::Mutex;

use tauri::Manager;

use db::Db;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir).ok();
            let db = Db::open(&dir.join("vibeauditt.db")).map_err(|e| e.to_string())?;
            app.manage(Mutex::new(db));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::run_audit,
            commands::audit_database,
            commands::list_audits,
            commands::get_audit,
            commands::delete_audit,
            commands::get_catalog_info,
            commands::update_catalog,
            commands::save_report_pdf,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

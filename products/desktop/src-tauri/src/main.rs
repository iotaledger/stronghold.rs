#![cfg_attr(
  all(not(debug_assertions), target_os = "windows"),
  windows_subsystem = "windows"
)]

mod menu;
use tauri::{CustomMenuItem, Manager, SystemTray, SystemTrayEvent, SystemTrayMenu, SystemTrayMenuItem};

use tauri_plugin_authenticator::TauriAuthenticator;
use tauri_plugin_stronghold::TauriStronghold;

use serde::{ser::Serializer, Deserialize, Serialize};

type Result<T> = std::result::Result<T, CommandError<'static>>;

#[derive(Deserialize)]
struct UnlockPayload {
  pwd: String,
  path: String,
}

#[tauri::command]
fn unlock<'a>(payload: UnlockPayload) -> Result<Response<'a>> {
  let response = Response {
    message: "12D3KooWLyEaoayajvfJktzjvvNCe9XLxNFMmPajsvrHeMkgajAA",
  };
  Ok(response)
}

#[derive(Serialize)]
struct Response<'a> {
  message: &'a str,
}

#[derive(Debug, Clone)]
struct CommandError<'a> {
  message: &'a str,
}

impl<'a> CommandError<'a> {
  fn new(message: &'a str) -> Self {
    Self { message }
  }
}

impl<'a> std::fmt::Display for CommandError<'a> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.message)
  }
}

impl<'a> std::error::Error for CommandError<'a> {}

impl Serialize for CommandError<'_> {
  fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    serializer.serialize_str(self.message)
  }
}

fn main() {
  let context = tauri::generate_context!();
  let bundle_identifier = context.config().tauri.bundle.identifier.clone();
  tauri::Builder::default()
    .plugin(TauriStronghold::default())
    .plugin(TauriAuthenticator::default())
    .system_tray(
      SystemTray::new()
        .with_menu(SystemTrayMenu::new()
        .add_item(CustomMenuItem::new("show".into(), "Show"))
        .add_item(CustomMenuItem::new("hide".into(), "Hide"))
        .add_item(CustomMenuItem::new("quit".into(), "Quit")))
    )
    .on_system_tray_event(|app, event| match event {
      SystemTrayEvent::LeftClick {
        position: _,
        size: _,
        ..
      } => {
        let window = app.get_window("main").unwrap();
        window.unminimize().unwrap();
        window.set_focus().unwrap();
      }
      SystemTrayEvent::MenuItemClick { id, .. } => match id.as_str() {
        "quit" => {
          std::process::exit(0);
        }
        "show" => {
          let window = app.get_window("main").unwrap();
          window.show().unwrap();
          window.unminimize().unwrap();
          window.set_focus().unwrap();
        }
        "hide" => {
            let window = app.get_window("main").unwrap();
            window.minimize().unwrap();
            window.hide().unwrap();
        }
        _ => {}
      },
      _ => {}
    })
    .menu(menu::get())
    .on_menu_event(move |event| match event.menu_item_id().as_str() {
      "create" | "swap" | "portfolio" => {
        let _ = event.window().eval(&format!(
          r#"
          window.location.href = (window.location.origin + '/' + "{}")
        "#,
          event.menu_item_id()
        ));
      }
      "notification" => {
        let bundle_identifier = bundle_identifier.clone();
        tauri::async_runtime::spawn(async move {
          tauri::api::notification::Notification::new(&bundle_identifier)
            .title("Stronghold")
            .body("This is a demo notification")
            .show()
            .unwrap();
        });
      }
      _ => {}
    })
    .invoke_handler(tauri::generate_handler![unlock])
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}

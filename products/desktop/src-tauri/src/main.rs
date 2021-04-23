#![cfg_attr(
  all(not(debug_assertions), target_os = "windows"),
  windows_subsystem = "windows"
)]

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

use tauri_plugin_authenticator::TauriAuthenticator;
use tauri_plugin_stronghold::TauriStronghold;

fn main() {
  tauri::Builder::default()
    .plugin(TauriStronghold::default())
    .plugin(TauriAuthenticator::default())
    .invoke_handler(tauri::generate_handler![unlock])
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}

#![cfg_attr(
  all(not(debug_assertions), target_os = "windows"),
  windows_subsystem = "windows"
)]

use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct UnlockPayload {
  pwd: String,
  path: String,
}

#[derive(Deserialize)]
#[serde(tag = "cmd", rename_all = "camelCase")]
enum Cmd {
  Unlock {
    payload: UnlockPayload,
    callback: String,
    error: String,
  },
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

use tauri_plugin_stronghold::TauriStronghold;
use tauri_plugin_authenticator::TauriAuthenticator;
x
fn main() {
  tauri::AppBuilder::new()
    .plugin(TauriStronghold {})
    .plugin(TauriAuthenticator {})
    .invoke_handler(|_webview, arg| {
      use Cmd::*;
      match serde_json::from_str(arg) {
        Err(e) => Err(e.to_string()),
        Ok(command) => {
          match command {
            Unlock { payload, callback, error } => tauri::execute_promise(
              _webview,
              move || {
                let response = Response {
                  message: "12D3KooWLyEaoayajvfJktzjvvNCe9XLxNFMmPajsvrHeMkgajAA",
                };
                Ok(response)
              },
              callback,
              error,
            ),
          }
          Ok(())
        }
      }
    })
    .build()
    .run();
}

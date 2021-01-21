#![cfg_attr(
  all(not(debug_assertions), target_os = "windows"),
  windows_subsystem = "windows"
)]

use iota_stronghold::{home_dir, naive_kdf, Location, RecordHint, StatusMessage, Stronghold};

use futures::executor::block_on;

use riker::actors::*;

use std::path::{Path, PathBuf};

use std::{thread, time};


// create a line error with the file and the line number
#[macro_export]
macro_rules! line_error {
    () => {
        concat!("Error at ", file!(), ":", line!())
    };
    ($str:expr) => {
        concat!($str, " @", file!(), ":", line!())
    };
}

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



fn main() {
  let system = ActorSystem::new().expect(line_error!());
  let client_path = b"actor_path".to_vec();
  let mut stronghold = Stronghold::init_stronghold_system(system, client_path.clone(), vec![]);

  tauri::AppBuilder::new()
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
                  message: "Response from Rust.",
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

use tauri::{CustomMenuItem, Menu, MenuItem, Submenu};

pub fn get() -> Menu<String> {
  #[allow(unused_mut)]
  let mut peer = CustomMenuItem::new("peer".into(), "New PeerID");
  #[allow(unused_mut)]
  let mut swarm = CustomMenuItem::new("swarm".into(), "Link to swarm");
  #[cfg(target_os = "macos")]
  {
    peer = peer.native_image(tauri::NativeImage::Add);
    swarm = swarm.native_image(tauri::NativeImage::Refresh);
  }
  Menu::new()
    .add_submenu(Submenu::new(
      "Edit",
      Menu::new()
        .add_native_item(MenuItem::Undo)
        .add_native_item(MenuItem::Redo)
        .add_native_item(MenuItem::Cut)
        .add_native_item(MenuItem::Copy)
        .add_native_item(MenuItem::Paste)
        .add_native_item(MenuItem::Separator)
        .add_native_item(MenuItem::Quit),

    ))
    .add_submenu(Submenu::new(
      "Swarm",
      Menu::new().add_item(peer).add_item(swarm),
    ))
}

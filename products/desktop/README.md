# Stronghold (stronghold-tauri)

Desktop App for Stronghold Systems Verification.

In order to develop this system, you will have to have at least rustc 1.52.1 installed, nodejs 14+, and fulfilled all requirements for Tauri Development as you can see at https://tauri.studio/en/docs/getting-started/intro

## Install the dependencies
```bash
yarn
```

### Start the app in development mode (hot-code reloading, error reporting, etc.)
```bash
yarn tauri dev
```

### Lint the files
```bash
yarn run lint
```

### Build the app for production
```bash
yarn tauri build
```

### Updating
Be sure to purge the yarn.lock and Cargo.lock if you are changing deps.
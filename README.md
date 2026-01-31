# RADIUS Log Browser (NPS) - Rust Edition
)

A high-performance, portable viewer for Microsoft NPS/IAS RADIUS logs (XML format).
Built with **Rust** and **egui** for maximum speed and zero dependencies.

> [!NOTE]
> This project is a **Rust port** of the original [RADIUS-Log-Browser](https://github.com/burnacid/RADIUS-Log-Browser) by burnacid.

## 🚀 Features

- **Blazing Fast**: Parses large XML logs (GBs) in seconds using threading.
- **Portable**: Single `.exe` file (~4.1MB), no config, no installation.
- **Smart Filtering**:
  - Filter by User, MAC, IP, Server, or Reason.
  - Contextual "Session" view (Right-click -> Filter by Session ID).
  - "Failed Sessions Only" mode.
  - "Time Window" analysis (±60s context).
- **Export**: Export filtered results to **Excel (.xlsx)** with native formatting.
- **Modern UI**: Dark/Light mode, resizable columns, keyboard navigation.

## 🛠️ Build

Requirements: [Rust Toolchain](https://rustup.rs/)

```bash
# Clone
git clone <repo>
cd RADIUS-Log-Browser

# Build (Optimized)
cargo build --release
```

The executable will be in `target/release/radius-log-browser-rs.exe`.

## 📦 Usage

1. Launch `RadiusLogBrowser_Portable.exe`.
2. Click "Open Log File" (select your IAS/NPS `.log` or `.xml`).
3. Browse, filter, right-click rows for actions.

## ⚖️ License
MIT / Apache 2.0

use std::io;

#[cfg(windows)]
fn main() -> io::Result<()> {
    let mut res = winres::WindowsResource::new();
    res.set_icon("app.ico");
    
    // Métadonnées de l'exécutable
    res.set("ProductName", "RADIUS Log Browser");
    res.set("FileDescription", "High-performance viewer for Microsoft NPS/IAS RADIUS logs");
    res.set("ProductVersion", "1.0.0");
    res.set("FileVersion", "1.0.0");
    res.set("CompanyName", "Olivier Noblanc");
    res.set("LegalCopyright", "© 2026 Olivier Noblanc");
    res.set("OriginalFilename", "radius-log-browser-rs.exe");
    res.set("InternalName", "radius-log-browser-rs");
    res.set("Comments", "https://github.com/olivier-noblanc/nps-radius-log-viewer");
    
    res.compile()
}

#[cfg(not(windows))]
fn main() -> io::Result<()> {
    Ok(())
}

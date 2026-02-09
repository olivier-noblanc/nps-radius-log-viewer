use std::io;

#[cfg(windows)]
fn main() -> io::Result<()> {
    let mut res = winres::WindowsResource::new();
    
    // Set icon with explicit ID 1
    res.set_icon_with_id("assets/app.ico", "1");
    
    // Metadata (already present in your code)
    res.set("ProductName", "RADIUS Log Browser");
    res.set("FileDescription", "High-performance viewer for Microsoft NPS/IAS RADIUS logs");
    res.set("ProductVersion", "1.0.0");
    res.set("FileVersion", "1.0.0");
    res.set("CompanyName", "Olivier Noblanc");
    res.set("LegalCopyright", "© 2026 Olivier Noblanc");
    res.set("OriginalFilename", "radius-log-browser-rs.exe");
    res.set("InternalName", "radius-log-browser-rs");
    res.set("Comments", "https://github.com/olivier-noblanc/nps-radius-log-viewer");
    
    // ADDING MANIFEST: Informs Windows that the binary is "Standard" (asInvoker)
    res.set_manifest(r#"
    <assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0" xmlns:asmv3="urn:schemas-microsoft-com:asm.v3">
        <dependency>
            <dependentAssembly>
                <assemblyIdentity
                    type="win32"
                    name="Microsoft.Windows.Common-Controls"
                    version="6.0.0.0"
                    processorArchitecture="*"
                    publicKeyToken="6595b64144ccf1df"
                    language="*"
                />
            </dependentAssembly>
        </dependency>
        <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
            <security>
                <requestedPrivileges>
                    <requestedExecutionLevel level="asInvoker" uiAccess="false" />
                </requestedPrivileges>
            </security>
        </trustInfo>
    </assembly>
    "#);
    
    res.compile()
}

#[cfg(not(windows))]
fn main() -> io::Result<()> {
    Ok(())
}

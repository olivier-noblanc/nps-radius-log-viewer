use std::io;

#[cfg(windows)]
fn main() -> io::Result<()> {
    let mut res = winres::WindowsResource::new();
    res.set_icon("app.ico");
    res.compile()
}

#[cfg(not(windows))]
fn main() -> io::Result<()> {
    Ok(())
}

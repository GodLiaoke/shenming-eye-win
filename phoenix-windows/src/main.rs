#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
mod app;
mod atomic_store;
mod authorization;
#[cfg(windows)]
mod capture;
mod lifecycle;
#[cfg(windows)]
mod local_engine;
#[cfg(windows)]
mod log;
#[cfg(windows)]
mod ui;

#[cfg(windows)]
fn main() {
    if let Err(error) = ui::run() {
        app::show_error(&format!("{error:#}"));
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("Phoenix CodeV Windows requires Windows 10/11 x64");
}

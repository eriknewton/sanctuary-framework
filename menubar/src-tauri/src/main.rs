// Prevents additional console window on Windows in release. Has no effect on macOS.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    sanctuary_menubar_lib::run();
}

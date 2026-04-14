// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// Hot reload trigger
fn main() {
    datapilot_scout_lib::run()
}

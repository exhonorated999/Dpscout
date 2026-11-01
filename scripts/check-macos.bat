@echo off
rem Cross-compile check of the portable edition for macOS, from Windows.
rem No Mac or Apple SDK needed: zig supplies the C toolchain for the bundled
rem C deps (sqlite etc.). Builds the lib as rlib only, so nothing links
rem against Apple frameworks. Signing/bundling still needs a real Mac.
rem
rem One-time setup:
rem   rustup target add aarch64-apple-darwin x86_64-apple-darwin
rem   cargo install cargo-zigbuild --locked
rem   uv tool install ziglang        (provides python-zig.exe)
rem
rem Usage: scripts\check-macos.bat [aarch64^|x86_64]
setlocal
set ARCH=%1
if "%ARCH%"=="" set ARCH=aarch64
if not defined CARGO_ZIGBUILD_ZIG_PATH (
  for /f "delims=" %%Z in ('where python-zig 2^>nul') do set "CARGO_ZIGBUILD_ZIG_PATH=%%Z"
)
cd /d "%~dp0..\src-tauri"
cargo-zigbuild rustc --target %ARCH%-apple-darwin --features demo,portable --lib --crate-type rlib --target-dir target\mac --message-format short
exit /b %ERRORLEVEL%

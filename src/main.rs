//! Entry point: GUI when launched without arguments, CLI otherwise.
//!
//! The binary is linked as a Windows GUI application, so double-clicking it never
//! flashes a console window. The command line interface still works because we
//! either inherit the std handles of the launching shell or attach to its console
//! before the first byte is printed.

#![cfg_attr(all(windows, not(test)), windows_subsystem = "windows")]

mod cli;
mod gui;

#[cfg(windows)]
mod console {
    //! Minimal Win32 console plumbing (no extra crate needed).

    use std::ffi::c_void;

    const ATTACH_PARENT_PROCESS: u32 = 0xFFFF_FFFF;
    const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6; // -10
    const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5; // -11
    const STD_ERROR_HANDLE: u32 = 0xFFFF_FFF4; // -12
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const OPEN_EXISTING: u32 = 3;
    const INVALID_HANDLE_VALUE: isize = -1;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn AttachConsole(process_id: u32) -> i32;
        fn AllocConsole() -> i32;
        fn GetStdHandle(std_handle: u32) -> *mut c_void;
        fn SetStdHandle(std_handle: u32, handle: *mut c_void) -> i32;
        fn CreateFileW(
            file_name: *const u16,
            desired_access: u32,
            share_mode: u32,
            security_attributes: *mut c_void,
            creation_disposition: u32,
            flags_and_attributes: u32,
            template_file: *mut c_void,
        ) -> *mut c_void;
    }

    fn valid(handle: *mut c_void) -> bool {
        !handle.is_null() && handle as isize != INVALID_HANDLE_VALUE
    }

    unsafe fn open_device(name: &str) -> *mut c_void {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        }
    }

    fn bind(device: &str, which: u32) {
        unsafe {
            let handle = open_device(device);
            if valid(handle) {
                SetStdHandle(which, handle);
            }
        }
    }

    /// Make `println!` reach a terminal before the CLI starts talking.
    ///
    /// 1. Handles inherited from cmd.exe / PowerShell (incl. pipes) are used as is.
    /// 2. Otherwise attach to the console of the launching shell.
    /// 3. Otherwise (dragged onto the exe, started from Explorer) open a console.
    pub fn prepare_stdio() {
        unsafe {
            if valid(GetStdHandle(STD_OUTPUT_HANDLE)) {
                return;
            }
            if AttachConsole(ATTACH_PARENT_PROCESS) == 0 && AllocConsole() == 0 {
                return;
            }
            bind("CONOUT$", STD_OUTPUT_HANDLE);
            bind("CONOUT$", STD_ERROR_HANDLE);
            bind("CONIN$", STD_INPUT_HANDLE);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        // No console here on purpose: the GUI must never flash a terminal.
        std::process::exit(gui::run());
    }
    #[cfg(windows)]
    console::prepare_stdio();
    std::process::exit(cli::run(&args));
}

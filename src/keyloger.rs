use std::ptr::null_mut;
use windows_sys::Win32::Foundation::LRESULT;
use windows_sys::Win32::Foundation::WPARAM;
use windows_sys::Win32::Foundation::LPARAM;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
use windows_sys::Win32::UI::WindowsAndMessaging::CallNextHookEx;
use windows_sys::Win32::UI::WindowsAndMessaging::GetMessageA;
use windows_sys::Win32::UI::WindowsAndMessaging::KBDLLHOOKSTRUCT;
use windows_sys::Win32::UI::WindowsAndMessaging::SetWindowsHookExA;
const WH_KEYBOARD_LL: i32 = 13;

unsafe extern "system" fn hook_callback(code:i32, wparam:WPARAM, lparam:LPARAM) -> LRESULT{
        let key = *(lparam as *const KBDLLHOOKSTRUCT);
        if code >= 0{
            println!("{}",key.vkCode);
        }
        return CallNextHookEx(0, code, wparam, lparam);
}



unsafe fn setup_hook(){
    
    let hinst: isize = GetModuleHandleA(null_mut());
    SetWindowsHookExA(
        WH_KEYBOARD_LL, 
        Some(hook_callback), 
        hinst, 
        0);
        GetMessageA(null_mut(), 0, 0, 0);
}

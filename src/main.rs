pub mod injector;

use injector::shellcode_injector::shellcode_injector;
use injector::hollowing_injector::hollowing_injector;
use injector::thread_injector::thread_injector;

fn main() {
    //thread_injector("explorer.exe", "shellcode/w64-exec-calc-shellcode-func.bin");
    hollowing_injector();
}

//    copy(shellcode.as_ptr(), addr.cast(), shellcode_size);
    //let args: Vec<String> = env::args().collect();
    // let pid: &String = &args[1];
   //let pid: u32 = match pid.trim().parse() {Ok(n) => {n}, Err(_) => {eprint!("Not an numbers ");return;}};
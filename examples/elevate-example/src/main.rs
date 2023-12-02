use elevated::is_elevated;
use serde::{Deserialize, Serialize};

fn main() {
    println!(
        "这里是以普通权限执行的代码：is_elevated={}, pid={}",
        is_elevated(),
        std::process::id()
    );
    let ret1 = admin_right("Hello Rust".to_string());
    println!("ret1: {}", ret1);
    let ret2 = admin_right2("Hello Rust".to_string());
    println!("ret2: {:#?}", ret2);
}

#[elevated::elevated]
fn admin_right(msg: String) -> u32 {
    let pid = std::process::id();
    println!(
        "这里是以管理员权限执行的代码：msg={}, is_elevated={}, pid={}",
        msg,
        is_elevated(),
        pid,
    );
    pid
}

#[derive(Serialize, Deserialize, Debug)]
struct ComplexValue {
    pid: u32,
    args: Vec<String>,
}
#[elevated::elevated]
fn admin_right2(msg: String) -> ComplexValue {
    let pid = std::process::id();
    println!(
        "这里是以管理员权限执行的代码：msg={}, is_elevated={}, pid={}",
        msg,
        is_elevated(),
        pid,
    );
    ComplexValue {
        pid,
        args: std::env::args().collect(),
    }
}

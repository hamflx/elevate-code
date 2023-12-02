use elevated::is_elevated;

fn main() {
    println!(
        "这里是以普通权限执行的代码：is_elevated={}, pid={}",
        is_elevated(),
        std::process::id()
    );
    admin_right("Hello Rust".to_string());
    admin_right2("Hello Rust".to_string());
    admin_right3("Hello Rust".to_string());
}

#[elevated::elevated]
fn admin_right(msg: String) {
    println!(
        "这里是以管理员权限执行的代码：msg={}, is_elevated={}, pid={}",
        msg,
        is_elevated(),
        std::process::id(),
    );
}

#[elevated::elevated]
fn admin_right2(msg: String) {
    println!(
        "这里是以管理员权限执行的代码：msg={}, is_elevated={}, pid={}",
        msg,
        is_elevated(),
        std::process::id(),
    );
}

#[elevated::elevated]
fn admin_right3(msg: String) {
    println!(
        "这里是以管理员权限执行的代码：msg={}, is_elevated={}, pid={}",
        msg,
        is_elevated(),
        std::process::id(),
    );
}

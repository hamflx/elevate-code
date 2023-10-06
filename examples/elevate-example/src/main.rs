fn main() {
    println!("这里是以普通权限执行的代码");
    admin_right("Hello Rust".to_string());
}

#[elevate_code::elevate_code]
fn admin_right(msg: String) {
    println!("这里是以管理员权限执行的代码：{msg}");
}

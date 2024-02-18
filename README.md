# elevated

通过一个宏，自动将函数包装为管理员权限执行，使用方法：

```rust
#[elevated::main]
fn main() {
    println!("这里是以普通权限执行的代码");
    admin_right("Hello Rust".to_string());
}

#[elevated::elevated]
fn admin_right(msg: String) {
    println!("这里是以管理员权限执行的代码：{msg}");
}
```

**注意，在 `elevated` 宏标记的函数中，不要使用全局变量，因为全局变量可能还没有初始化，而且，被标记的函数是使用新的进程启动的，全局变量的取值可能不对。**

**注意，被 `elevated` 宏标记的函数不可以重名。**

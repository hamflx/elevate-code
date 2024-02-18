use std::io::Write;

use serde::de::DeserializeOwned;

use crate::{
    create_paused_process, process::AutoTerminateProcess, ElevationRequest, NamedPipeServer,
    PipeClient, TaskInfo, GLOBAL_CLIENT,
};

pub fn execute_tasks() -> Result<(), String> {
    let mut client = PipeClient::new(&generate_pipe_name(std::process::id()))?;
    let message = client
        .read_buf_string()
        .map_err(|err| format!("read_to_string error: {err}"))?;
    let task: TaskInfo = serde_json::from_str(&message)
        .map_err(|err| format!("serde_json::from_str error: {err}"))?;
    let caller: fn(String) -> String = unsafe { std::mem::transmute(task.caller_offset) };
    let ret = caller(task.args);

    client
        .write_all(ret.as_bytes())
        .map_err(|err| format!("write_all error: {err}"))?;

    std::process::exit(0);
}

pub fn spawn_task<T>(caller: fn(String) -> String, args: String) -> Result<T, String>
where
    T: DeserializeOwned,
{
    // 创建一个暂停的进程，因为需要修改 Primary Token，必须要是暂停的。
    let child = create_paused_process()?;
    let terminate_guard = AutoTerminateProcess::new(child.dupe()?);
    let pid = child.pid();

    // 将新进程信息发送给管理员权限启动的进程，让其帮忙替换该进程的 Primary Token。
    GLOBAL_CLIENT.request(ElevationRequest::new(pid))?;

    // 在新进程代码运行之前，准备好一个管道。
    let pipe_name = generate_pipe_name(pid);
    let mut pipe = NamedPipeServer::new(&pipe_name)?;

    // 恢复进程执行。
    let child = child.run();

    // 将参数与函数地址发送给子进程，并等待返回值。
    let info = TaskInfo::new(0, String::new(), caller as *const () as usize, args);
    let payload = serde_json::to_string(&info).unwrap();
    pipe.accept()?;
    pipe.write(payload.as_bytes())
        .map_err(|err| format!("write error: {err}"))?;
    let message = pipe.read_buf_string()?;

    // 等待子进程结束。
    child.wait();

    drop(terminate_guard);
    Ok(serde_json::from_str(&message)
        .map_err(|err| format!("serde_json::from_str error: {err}"))?)
}

fn generate_pipe_name(pid: u32) -> String {
    format!("\\\\.\\pipe\\elevated_task_{}", pid)
}

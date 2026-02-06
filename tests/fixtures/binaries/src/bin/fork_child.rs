use std::process::ExitCode;

fn main() -> ExitCode {
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => {
            eprintln!("fork failed");
            ExitCode::FAILURE
        }
        0 => {
            // Child
            eprintln!("child pid={}", unsafe { libc::getpid() });
            ExitCode::SUCCESS
        }
        child_pid => {
            // Parent
            eprintln!("parent pid={}, child={child_pid}", unsafe { libc::getpid() });
            let mut status: i32 = 0;
            unsafe { libc::waitpid(child_pid, &mut status, 0) };
            ExitCode::SUCCESS
        }
    }
}

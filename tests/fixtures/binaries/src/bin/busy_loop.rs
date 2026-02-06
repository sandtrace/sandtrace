use std::process::ExitCode;

fn main() -> ExitCode {
    // Spin forever - used to test timeout enforcement
    loop {
        std::hint::spin_loop();
    }
    #[allow(unreachable_code)]
    ExitCode::SUCCESS
}

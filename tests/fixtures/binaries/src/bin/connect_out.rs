use std::net::TcpStream;
use std::process::ExitCode;
use std::time::Duration;

fn main() -> ExitCode {
    // Try to connect to an external address
    // This should be blocked by network namespace / policy
    let addr = std::env::args().nth(1).unwrap_or_else(|| "1.2.3.4:80".to_string());

    match TcpStream::connect_timeout(
        &addr.parse().expect("invalid address"),
        Duration::from_secs(2),
    ) {
        Ok(_) => {
            eprintln!("connected successfully (unexpected in sandbox)");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("connect failed: {e}");
            ExitCode::FAILURE
        }
    }
}

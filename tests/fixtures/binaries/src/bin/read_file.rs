use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let path = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: read_file <path>");
            return ExitCode::from(2);
        }
    };

    match fs::read_to_string(&path) {
        Ok(contents) => {
            print!("{contents}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

use std::ffi::CString;
use std::process::ExitCode;
use std::ptr;

fn main() -> ExitCode {
    let source = CString::new("none").unwrap();
    let target = CString::new("/tmp").unwrap();
    let fstype = CString::new("tmpfs").unwrap();

    let ret = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            0,
            ptr::null(),
        )
    };

    if ret == 0 {
        eprintln!("mount succeeded (unexpected in sandbox)");
        ExitCode::SUCCESS
    } else {
        let errno = std::io::Error::last_os_error();
        eprintln!("mount failed: {errno}");
        ExitCode::FAILURE
    }
}

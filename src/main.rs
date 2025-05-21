use std::ptr;
use std::ffi::CString;

fn main() {
    let oidname = CString::new("net.inet.tcp.ktlslist").unwrap();
    let mut size: libc::size_t = 0;
    let e = unsafe {
	libc::sysctlbyname(oidname.as_ptr() as *const i8,
			   ptr::null_mut(), &raw mut size,
			   ptr::null_mut(), 0)
    };
    println!("sysctl returned {}", e);
}

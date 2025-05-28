use std::alloc::*;
use std::ffi::CString;
use std::process;
use std::ptr;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(version,
	  about = "Dump tcp connections with ktls offload",
	  long_about = None)]
struct KTCPArgs {
    /// Output debugging information
    #[arg(short, long, action = clap::ArgAction::Count)]
    debug: u8,

    /// Dump keys
    #[arg(short, long)]
    keys: bool,
}

fn c_char_ptr_to_string(ptr: *const libc::c_char) -> String {
    unsafe { std::ffi::CStr::from_ptr(ptr).to_str().unwrap().to_string() }
}

fn strerror(errno: i32) -> String {
    unsafe { c_char_ptr_to_string(libc::strerror(errno)) }
}

fn get_errno() -> libc::c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap()
}

fn fetch_klts_table(dump_keys: bool) -> (*const libc::xktls_session,
	usize, libc::inp_gen_t) {
    let oidname = if dump_keys {
	"net.inet.tcp.ktlslist_wkeys"
    } else {
	"net.inet.tcp.ktlslist"
    };
    let oidnamec = CString::new(oidname).unwrap();
    let mut sz: libc::size_t = 0;
    let e = unsafe {
        libc::sysctlbyname(
            oidnamec.as_ptr() as *const i8,
            ptr::null_mut(),
            &raw mut sz,
            ptr::null_mut(),
            0,
        )
    };
    if e != 0 {
        let errno = get_errno() as i32;
	eprintln!("sysctl size {}: {}", oidname, strerror(errno));
        std::process::exit(1);
    }

    let res = loop {
        let layout = match Layout::from_size_align(sz,
	  std::mem::align_of::<libc::xktls_session>()) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Cannot alloc layout {}", e);
                process::exit(1);
            }
        };

        let buf: *mut u8 = unsafe { alloc(layout) };

        let mut ksz: libc::size_t = sz;
        let e = unsafe {
            libc::sysctlbyname(
                oidnamec.as_ptr() as *const i8,
                buf as *mut libc::c_void,
                &raw mut ksz,
                ptr::null_mut(),
                0,
            )
        };
        if e != 0 {
            let errno = get_errno() as i32;
	    eprintln!("sysctl {}: {}", oidname, strerror(errno));
            process::exit(1);
        }

        if ksz != sz {
            sz = ksz;
            unsafe { dealloc(buf, layout) };
            continue;
        }
        let xig: &libc::xinpgen = unsafe {
	    &*std::mem::transmute::<*mut u8, *const libc::xinpgen>(buf)
	};
        let exig: &libc::xinpgen = unsafe {
            &*std::mem::transmute::<*mut u8, *const libc::xinpgen>(
                buf.add(sz - std::mem::size_of::<libc::xinpgen>()),
            )
        };
        let ktlss: *const libc::xktls_session = unsafe {
            std::mem::transmute::<*mut u8, *const libc::xktls_session>(
                buf.add(std::mem::size_of::<libc::xinpgen>()))
        };
        break (ktlss, exig.xig_count as usize, xig.xig_gen);
    };
    res
}

fn dump_addr_v4(a: &libc::in_dependaddr) -> String {
    let addr = std::net::Ipv4Addr::from_bits(u32::to_be(unsafe {
	a.id46_addr.ia46_addr4.s_addr
    }));
    format!("{}", addr)
}

fn dump_addr_v6(a: &libc::in_dependaddr) -> String {
    let addr = std::net::Ipv6Addr::from_bits(u128::from_be_bytes(unsafe {
	a.id6_addr.s6_addr
    }));
    format!("{}", addr)
}

fn dump_addr(a: &libc::in_dependaddr, ipv6: bool) -> String {
    if ipv6 {
	dump_addr_v6(a)
    } else {
	dump_addr_v4(a)
    }
}

fn dump_endpoints(ie: &libc::in_endpoints, ipv6: bool) -> String {
    let mut res = String::from("");
    res.push_str(&dump_addr(&ie.ie_dependfaddr, ipv6));
    res.push('\t');
    res.push_str(&format!("{}", u16::from_be(ie.ie_fport)));
    res.push('\t');
    res.push_str(&dump_addr(&ie.ie_dependladdr, ipv6));
    res.push('\t');
    res.push_str(&format!("{}", u16::from_be(ie.ie_lport)));
    res
}

fn dump_conninfo(ci: &libc::in_conninfo) -> String {
    let mut res = String::from("");
    let ipv6 = (ci.inc_flags & libc::INC_ISIPV6) != 0;
    res.push_str(&dump_endpoints(&ci.inc_ie, ipv6));
    if ci.inc_fibnum != 0 {
	res.push('\t');
	res.push_str(&format!("fib={}", ci.inc_fibnum));
    }
    res
}

fn dump_ifnamen(name: &[u8]) -> String {
    let mut res = String::from("");
    for n in name {
	if *n == 0 {
	    break;
	}
	res.push(unsafe { char::from_u32_unchecked(*n as u32) });
    }
    res
}

fn dump_key(ptr: *const u8, len: u16) -> String {
    let mut res = String::from("");
    let mut first = true;
    res.push('[');
    for x in 0..len {
	if first {
	    first  = false;
	} else {
	    res.push(' ');
	};
	unsafe {
	    let ptr1: *const u8 = ptr.add(x as usize);
	    res.push_str(&format!("{:02x}", *ptr1));
	}
    }
    res.push(']');
    res
}

fn dump_xktls_od(xtls_od: &libc::xktls_session_onedir, rcv: bool, vlan: u16,
	 ptr: *const u8) -> String {
    let mut res = String::from("");
    res.push_str(&format!("tls_vmajor={} tls_vminor={}",
	xtls_od.tls_vmajor, xtls_od.tls_vminor));
    res.push_str(&format!(" cipher_algo={}", xtls_od.cipher_algorithm));
    if xtls_od.cipher_key_len > 0 {
	res.push_str(&format!(" cipher_key={}", dump_key(ptr,
	    xtls_od.cipher_key_len)));
    }
    res.push_str(&format!(" auth_algo={}", xtls_od.auth_algorithm));
    if xtls_od.auth_key_len > 0 {
	res.push_str(&format!(" auth_key={}", dump_key(unsafe { ptr.add(
	    xtls_od.cipher_key_len as usize) },
	    xtls_od.auth_key_len)));
    }
    // XXX
    if xtls_od.ifnet[0] != 0 {
	res.push_str(" oflif=");
	res.push_str(&dump_ifnamen(&xtls_od.ifnet));
    }
    if rcv && vlan != 0 {
	res.push('\t');
	res.push_str(&format!("vlan={}", vlan));
    }
    res
}

fn dump_xktls(xktls: &libc::xktls_session) -> String {
    let mut res = String::from("");
    let ptr: *const u8 = unsafe {
	std::mem::transmute::<&libc::xktls_session, *const u8>(xktls).
	    add(std::mem::size_of::<libc::xktls_session>())
    };

    res.push_str(&dump_conninfo(&xktls.coninf));
    res.push('\t');
    res.push_str(&format!("rcv=({})", dump_xktls_od(
	&xktls.rcv, true, xktls.rx_vlan_id as u16, ptr)));
    res.push('\t');
    res.push_str(&format!("snd=({})", dump_xktls_od(&xktls.snd, false, 0,
	unsafe { ptr.add(xktls.rcv.cipher_key_len as usize +
	    xktls.rcv.auth_key_len as usize) })));
    res
}

fn main() {
    let args = KTCPArgs::parse();
    let (xktlss, count, inpgen) = fetch_klts_table(args.keys);
    if args.debug > 0 {
	eprintln!("KTLS table from kernel: {} connections, xinpcb generation {}",
		  count, inpgen);
    }
    let mut i: usize = 0;
    if count > 0 {
	let mut xktls: &libc::xktls_session = unsafe { &*xktlss };
	loop {
	    if xktls.rcv.gennum < inpgen && xktls.snd.gennum < inpgen {
		println!("{}", dump_xktls(xktls));
	    } else if args.debug > 1 {
		println!("conn {} skipped, generations rcv {} snd {}",
			 i, xktls.rcv.gennum, xktls.snd.gennum);
	    }
	    i += 1;
	    if i >= count {
		break;
	    }
	    xktls = unsafe {
		let rptr: *const u8 = std::mem::transmute::<
		    *const libc::xktls_session, *const u8>(xktls);
		&*std::mem::transmute::<*const u8, *const libc::xktls_session>(
		    rptr.add(xktls.tsz.try_into().unwrap()))
	    };
	}
    }
}

/*-
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This software was developed by Konstantin Belousov <kib@FreeBSD.org>
 * under sponsorship from NVidia networking.
 */

use std::alloc::*;
use std::ffi::CString;
use std::process;
use std::ptr;
use clap::Parser;
use serde::Serialize;

#[derive(Parser, Debug)]
#[command(version,
	  about = "List tcp connections with ktls offload",
	  long_about = None)]
struct KTCPArgs {
    /// Output debugging information
    #[arg(short, long, action = clap::ArgAction::Count)]
    debug: u8,

    /// Dump keys
    #[arg(short, long)]
    keys: bool,

    /// Dump into json
    #[arg(short, long)]
    json: bool,
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

#[derive(Serialize)]
struct TCPConn {
    laddr: std::net::IpAddr,
    lport: u16,
    faddr: std::net::IpAddr,
    fport: u16,
    fib: u16,
}

#[derive(Serialize)]
struct KTLSSessInfo {
    iv: Vec<u8>,
    cipher_algorithm: i32,
    cipher_key: Vec<u8>,
    auth_algorithm: i32,
    auth_key: Vec<u8>,
    max_frame_len: u16,
    tls_vmajor: u8,
    tls_vminor: u8,
    tls_hlen: u8,
    tls_tlen: u8,
    tls_bs: u8,
    flags: u8,
    vlan: u16,
    offload_ifnet: String,
    offload_drv_info: String,
}

#[derive(Serialize)]
struct KTLSTCPConn {
    ie: TCPConn,
    rcv: KTLSSessInfo,
    snd: KTLSSessInfo,
}

#[derive(Serialize)]
struct KTLSTCPConns {
    conns: Vec<KTLSTCPConn>,
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
            &*((xig as *const libc::xinpgen).map_addr(
		|x| x + sz - std::mem::size_of::<libc::xinpgen>()))
        };
        let ktlss: *const libc::xktls_session = unsafe {
            std::mem::transmute::<*mut u8, *const libc::xktls_session>(
                buf.add(std::mem::size_of::<libc::xinpgen>()))
        };
        break (ktlss, exig.xig_count as usize, xig.xig_gen);
    };
    res
}

fn dump_conninfo(ie: &TCPConn) -> String {
    let mut res = String::from("");
    res.push_str(&format!("{}\t{}\t{}\t{}",
	ie.faddr, ie.fport, ie.laddr, ie.lport));
    if ie.fib != 0 {
	res.push_str(&format!("\tfib={}", ie.fib));
    }
    res
}

fn dump_key(b: &Vec<u8>) -> String {
    let mut res = String::from("");
    let mut first = true;
    res.push('[');
    for x in b {
	if first {
	    first  = false;
	} else {
	    res.push(' ');
	};
	res.push_str(&format!("{:02x}", x));
    }
    res.push(']');
    res
}

fn dump_xktls_od(ktls_s: &KTLSSessInfo, args: &KTCPArgs) -> String {
    let mut res = String::from("");
    res.push_str(&format!("tls_vmajor={} tls_vminor={}",
	ktls_s.tls_vmajor, ktls_s.tls_vminor));
    res.push_str(&format!(" cipher_algo={}", ktls_s.cipher_algorithm));
    if ktls_s.cipher_key.len() > 0 && args.keys {
	res.push_str(&format!(" cipher_key={}", dump_key(&ktls_s.cipher_key)));
    }
    res.push_str(&format!(" auth_algo={}", ktls_s.auth_algorithm));
    if ktls_s.auth_key.len() > 0 && args.keys {
	res.push_str(&format!(" auth_key={}", dump_key(&ktls_s.auth_key)));
    }
    if ktls_s.iv.len() > 0 && args.keys {
	res.push_str(&format!(" iv={}", dump_key(&ktls_s.iv)));
    }
    if ktls_s.offload_ifnet.len() != 0 {
	res.push_str(&format!(" oflif={}", &ktls_s.offload_ifnet));
	if ktls_s.offload_drv_info.len() != 0 {
	    res.push_str(&format!(" drvinfo=\"{}\"",
		&ktls_s.offload_drv_info));
	}
    }
    if ktls_s.vlan != 0 {
	res.push_str(&format!(" vlan={}", ktls_s.vlan));
    }
    res
}

fn dump_xktls_conn(conn: &KTLSTCPConn, args: &KTCPArgs) -> String {
    let mut res = String::from("");
    res.push_str(&dump_conninfo(&conn.ie));
    res.push_str(&format!("\trcv=({})", &dump_xktls_od(&conn.rcv, args)));
    res.push_str(&format!("\tsnd=({})", &dump_xktls_od(&conn.snd, args)));
    res
}

fn dump_xktls_conns(conns: &KTLSTCPConns, args: &KTCPArgs) {
    for conn in &conns.conns {
	println!("{}", dump_xktls_conn(&conn, args))
    }
}

fn json_xktls_conns(conns: &KTLSTCPConns, _args: &KTCPArgs) {
    let j = serde_json::to_string(&conns).unwrap();
    println!("{}", j);
}

fn gather_key_bytes(ptr: *const u8, off: usize, sz: usize,
	op: bool) -> Vec::<u8> {
    let mut res = Vec::<u8>::new();
    if !op {
	return res;
    }
    for i in 0..sz {
	unsafe {
	    let ptr1: *const u8 = ptr.add(off + i);
	    res.push(*ptr1);
	}
    }
    res
}

fn parse_addr(a: &libc::in_dependaddr, ipv6: bool) -> std::net::IpAddr {
    if ipv6 {
	std::net::IpAddr::V6(std::net::Ipv6Addr::from_bits(
	    u128::from_be_bytes(unsafe { a.id6_addr.s6_addr })))
    } else {
	std::net::IpAddr::V4(std::net::Ipv4Addr::from_bits(
	    u32::to_be(unsafe { a.id46_addr.ia46_addr4.s_addr })))
    }
}

fn parse_endpoints(ci: &libc::in_conninfo) -> TCPConn {
    let ipv6 = (ci.inc_flags & libc::INC_ISIPV6) != 0;
    let res = TCPConn {
	lport: u16::from_be(ci.inc_ie.ie_lport),
	laddr: parse_addr(&ci.inc_ie.ie_dependladdr, ipv6),
	fport: u16::from_be(ci.inc_ie.ie_fport),
	faddr: parse_addr(&ci.inc_ie.ie_dependfaddr, ipv6),
	fib: ci.inc_fibnum,
    };
    res
}

fn bytes_to_string(name: &[u8]) -> String {
    let mut res = String::from("");
    for n in name {
	if *n == 0 {
	    break;
	}
	res.push(unsafe { char::from_u32_unchecked(*n as u32) });
    }
    res
}

fn parse_kern_data(xktlss: *const libc::xktls_session, count: usize,
	inpgen: libc::inp_gen_t, args: &KTCPArgs) -> KTLSTCPConns {
    let mut res = KTLSTCPConns {
	conns: Vec::<KTLSTCPConn>::new(),
    };
    if count == 0 {
	return res;
    }
    let mut i: usize = 0;
    let mut xktls: &libc::xktls_session = unsafe { &*xktlss };
    if xktls.fsz as usize != std::mem::size_of::<libc::xktls_session>() {
	eprintln!("Kernel ktls_session structure changed");
	if args.debug >= 2 {
	    eprintln!("My size {} kernel size {}",
		std::mem::size_of::<libc::xktls_session>(),
		xktls.fsz);
	}
        process::exit(1);
    }
    loop {
	if xktls.rcv.gennum <= inpgen && xktls.snd.gennum <= inpgen {
	    let ptr: *const u8 = unsafe {
		std::mem::transmute::<&libc::xktls_session, *const u8>(xktls).
		    add(std::mem::size_of::<libc::xktls_session>())
	    };
	    let mut pos: usize = 0;
	    let mut len: usize;

	    let iv_rcv = gather_key_bytes(xktls.rcv.iv.as_ptr(), 0,
		xktls.rcv.iv_len as usize, args.keys);

	    len = xktls.rcv.cipher_key_len as usize;
	    let cipher_rcv_key = gather_key_bytes(ptr, pos, len, args.keys);
	    pos += len;

	    len = xktls.rcv.auth_key_len as usize;
	    let auth_rcv_key = gather_key_bytes(ptr, pos, len, args.keys);
	    pos += len;

	    len = xktls.rcv.drv_st_len as usize;
	    let drv_st_rcv_bytes = gather_key_bytes(ptr, pos, len, true);
	    pos += len;
	    
	    let iv_snd = gather_key_bytes(xktls.snd.iv.as_ptr(), 0,
		xktls.snd.iv_len as usize, args.keys);

	    len = xktls.snd.cipher_key_len as usize;
	    let cipher_snd_key = gather_key_bytes(ptr, pos, len, args.keys);
	    pos += len;

	    len = xktls.snd.auth_key_len as usize;
	    let auth_snd_key = gather_key_bytes(ptr, pos, len, args.keys);
	    pos += len;

	    len = xktls.snd.drv_st_len as usize;
	    let drv_st_snd_bytes = gather_key_bytes(ptr, pos, len, true);

	    let conn = KTLSTCPConn {
		ie: parse_endpoints(&xktls.coninf),
		rcv: KTLSSessInfo {
		    iv: iv_rcv,
		    cipher_algorithm: xktls.rcv.cipher_algorithm,
		    cipher_key: cipher_rcv_key,
		    auth_key: auth_rcv_key,
		    auth_algorithm: xktls.rcv.auth_algorithm,
		    max_frame_len: xktls.rcv.max_frame_len,
		    tls_vmajor: xktls.rcv.tls_vmajor,
		    tls_vminor: xktls.rcv.tls_vminor,
		    tls_hlen: xktls.rcv.tls_hlen,
		    tls_tlen: xktls.rcv.tls_tlen,
		    tls_bs: xktls.rcv.tls_bs,
		    flags: xktls.rcv.flags,
		    vlan: xktls.rx_vlan_id as u16,
		    offload_ifnet: bytes_to_string(&xktls.rcv.ifnet),
		    offload_drv_info: bytes_to_string(&drv_st_rcv_bytes),
		},
		snd: KTLSSessInfo {
		    iv: iv_snd,
		    cipher_key: cipher_snd_key,
		    cipher_algorithm: xktls.snd.cipher_algorithm,
		    auth_key: auth_snd_key,
		    auth_algorithm: xktls.snd.auth_algorithm,
		    max_frame_len: xktls.snd.max_frame_len,
		    tls_vmajor: xktls.snd.tls_vmajor,
		    tls_vminor: xktls.snd.tls_vminor,
		    tls_hlen: xktls.snd.tls_hlen,
		    tls_tlen: xktls.snd.tls_tlen,
		    tls_bs: xktls.snd.tls_bs,
		    flags: xktls.snd.flags,
		    vlan: 0,
		    offload_ifnet: bytes_to_string(&xktls.snd.ifnet),
		    offload_drv_info: bytes_to_string(&drv_st_snd_bytes),
		},
	    };
	    res.conns.push(conn);
	} else if args.debug > 1 {
	    println!("conn {} skipped, generations rcv {} snd {}",
		 i, xktls.rcv.gennum, xktls.snd.gennum);
	}
	i += 1;
	if i >= count {
	    break;
	}
	xktls = unsafe {
	    &*((xktls as *const libc::xktls_session).map_addr(
		|x| x + (xktls.tsz as usize)))
	};
    }
    res
}

fn main() {
    let args = KTCPArgs::parse();
    let (xktlss, count, inpgen) = fetch_klts_table(args.keys);
    if args.debug > 0 {
	eprintln!("KTLS table from kernel: {} connections, xinpcb generation {}",
		  count, inpgen);
    }
    let conns = parse_kern_data(xktlss, count, inpgen, &args);
    if args.json {
	json_xktls_conns(&conns, &args);
    } else {
	dump_xktls_conns(&conns, &args);
    }
}

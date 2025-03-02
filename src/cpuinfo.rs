// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg(any(target_arch = "aarch64", target_arch = "arm64ec", target_arch = "powerpc64"))]

use std::{boxed::Box, path::Path, vec::Vec};

use fs_err as fs;

type Result<T, E = Box<dyn std::error::Error + Send + Sync>> = std::result::Result<T, E>;

/// CPU feature detection by reading a file.
///
/// - On Linux/NetBSD, reading `/proc/cpuinfo`.
/// - On FreeBSD/OpenBSD, reading `/var/run/dmesg.boot`.
///
/// This is used for testing to ensure that the result of the CPU feature
/// detection we are using matches the information we get from the other
/// approaches.
#[cfg(any(target_arch = "aarch64", target_arch = "arm64ec"))]
#[derive(Debug, Clone, Copy)]
pub struct ProcCpuinfo {
    pub lse: bool,
    pub lse2: Option<bool>,
    pub rcpc3: Option<bool>,
    pub lse128: Option<bool>,
}
#[cfg(target_arch = "powerpc64")]
#[derive(Debug, Clone, Copy)]
pub struct ProcCpuinfo {
    pub power8: bool,
    pub power9: bool,
    pub power10: Option<bool>,
}
impl ProcCpuinfo {
    #[cfg(any(target_arch = "aarch64", target_arch = "arm64ec"))]
    pub fn new() -> Result<Self> {
        if cfg!(any(target_os = "linux", target_os = "android", target_os = "netbsd")) {
            let text = fs::read_to_string("/proc/cpuinfo")?;
            // On qemu-user, there is no 'Features' section because the host's /proc/cpuinfo will be referred to.
            // TODO: check whether a runner is set instead.
            let features = text
                .lines()
                .find_map(|line| line.strip_prefix("Features"))
                .ok_or("no 'Features' section in /proc/cpuinfo")?
                .split_once(':')
                .unwrap()
                .1
                .split(' ')
                .map(str::trim)
                .collect::<Vec<_>>();
            eprintln_nocapture!("/proc/cpuinfo: Features={:?}", features);
            Ok(Self {
                lse: features.contains(&"atomics"),
                lse2: Some(features.contains(&"uscat")),
                lse128: Some(features.contains(&"lse128")),
                rcpc3: Some(features.contains(&"lrcpc3")),
            })
        } else if cfg!(target_os = "freebsd") {
            let text = fs::read_to_string("/var/run/dmesg.boot")?;
            let isa0 = text
                .lines()
                .find(|line| line.contains("Instruction Set Attributes 0"))
                .ok_or("no 'Instruction Set Attributes 0' section in /var/run/dmesg.boot")?
                .split_once('=')
                .unwrap()
                .1
                .trim()
                .strip_prefix('<')
                .unwrap()
                .strip_suffix('>')
                .unwrap()
                .split(',')
                .collect::<Vec<_>>();
            let mmf2 = text
                .lines()
                .find(|line| line.contains("Memory Model Features 2"))
                .ok_or("no 'Memory Model Features 2' section in /var/run/dmesg.boot")?
                .split_once('=')
                .unwrap()
                .1
                .trim()
                .strip_prefix('<')
                .unwrap()
                .strip_suffix('>')
                .unwrap()
                .split(',')
                .collect::<Vec<_>>();
            eprintln_nocapture!(
                "/var/run/dmesg.boot: Instruction Set Attributes 0={:?}, \
                                      Memory Model Features 2={:?}",
                isa0,
                mmf2,
            );
            Ok(Self {
                lse: isa0.contains(&"Atomic"),
                lse2: Some(mmf2.contains(&"AT")),
                // TODO
                lse128: None,
                rcpc3: None,
            })
        } else if cfg!(target_os = "openbsd") {
            let text = fs::read_to_string("/var/run/dmesg.boot")?;
            let features = text
                .lines()
                .filter_map(|line| line.strip_prefix("cpu0: "))
                .next_back()
                .ok_or("no 'cpu0' section in /var/run/dmesg.boot")?
                .trim()
                .split(',')
                .collect::<Vec<_>>();
            eprintln_nocapture!("/var/run/dmesg.boot: Features={:?}", features);
            Ok(Self {
                lse: features.contains(&"Atomic"),
                // /var/run/dmesg.boot on OpenBSD doesn't have field for lse2
                lse2: None,
                // TODO
                lse128: None,
                rcpc3: None,
            })
        } else {
            if !cfg!(windows) {
                assert!(!Path::new("/proc/cpuinfo").exists());
                assert!(!Path::new("/var/run/dmesg.boot").exists());
            }
            Err("unsupported OS".into())
        }
    }
    #[cfg(target_arch = "powerpc64")]
    pub fn new() -> Result<Self> {
        if cfg!(any(target_os = "linux", target_os = "android", target_os = "netbsd")) {
            let text = fs::read_to_string("/proc/cpuinfo")?;
            // On qemu-user, there is no 'cpu' section because the host's /proc/cpuinfo will be referred to.
            // TODO: check whether a runner is set instead.
            let cpu = text
                .lines()
                .find_map(|line| line.strip_prefix("cpu"))
                .ok_or("no 'cpu' section in /proc/cpuinfo")?
                .split_once(':')
                .unwrap()
                .1
                .split(' ')
                .map(str::trim)
                .collect::<Vec<_>>();
            eprintln_nocapture!("/proc/cpuinfo: cpu={:?}", cpu);
            let v = cpu.iter().find(|v| v.starts_with("POWER")).ok_or("cpu is not POWER")?;
            let power10 = v.starts_with("POWER10");
            let power9 = power10 || v.starts_with("POWER9");
            let power8 = power9 || v.starts_with("POWER8");
            Ok(Self { power8, power9, power10: Some(power10) })
        } else if cfg!(target_os = "freebsd") {
            let text = fs::read_to_string("/var/run/dmesg.boot")?;
            let features2 = text
                .lines()
                .find(|line| {
                    line.split(|c: char| c.is_ascii_whitespace()).any(|f| f == "Features2")
                })
                .ok_or("no 'cpuN: Features2' section in /var/run/dmesg.boot")?
                .split_once('<')
                .unwrap()
                .1
                .trim()
                .strip_suffix('>')
                .unwrap()
                .split(',')
                .collect::<Vec<_>>();
            eprintln_nocapture!("/var/run/dmesg.boot: Features2={:?}", features2);
            Ok(Self {
                power8: features2.contains(&"ARCH207"),
                power9: features2.contains(&"ARCH300"),
                power10: None,
            })
        } else {
            assert!(!Path::new("/proc/cpuinfo").exists());
            assert!(!Path::new("/var/run/dmesg.boot").exists());
            Err("unsupported OS".into())
        }
    }
}

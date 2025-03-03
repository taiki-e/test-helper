// SPDX-License-Identifier: Apache-2.0 OR MIT

// Run-time CPU feature detection on non-x86 systems usually requires the use of
// platform APIs, and we define our own FFI bindings to those APIs.
//
// We use only one or two function(s) and a few types/constants per platform,
// but technically OS can change these APIs (unfortunately, some OSes don't care
// about breaking API/ABI between releases), so it is preferable to be able
// to detect them.
//
// See also https://github.com/rust-lang/libc/issues/570.

use std::process::Command;

use camino::{Utf8Path, Utf8PathBuf};
use duct::cmd;
use fs::os::unix::fs::symlink;
use fs_err as fs;
use quote::{format_ident, quote};
use regex::Regex;
use target_spec_json::{
    Arch::{self, *},
    Env::{self, *},
    Os::{self, *},
    TargetEndian::*,
    TargetSpec,
};

use crate::file::{self, workspace_root};

#[rustfmt::skip]
static TARGETS: &[Target] = &[
    Target {
        triples: &[
            // Linux (glibc)
            "aarch64-unknown-linux-gnu",
            "aarch64_be-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu_ilp32",
            "aarch64_be-unknown-linux-gnu_ilp32",
            "armv5te-unknown-linux-gnueabi",
            "armeb-unknown-linux-gnueabi", // TODO: v6
            "loongarch64-unknown-linux-gnu",
            "mips-unknown-linux-gnu",
            "mips64-unknown-linux-gnuabi64",
            "mips64el-unknown-linux-gnuabi64",
            "mipsel-unknown-linux-gnu",
            "mipsisa32r6-unknown-linux-gnu",
            "mipsisa32r6el-unknown-linux-gnu",
            "mipsisa64r6-unknown-linux-gnuabi64",
            "mipsisa64r6el-unknown-linux-gnuabi64",
            "powerpc-unknown-linux-gnu",
            "powerpc64-unknown-linux-gnu",
            "powerpc64le-unknown-linux-gnu",
            "riscv32gc-unknown-linux-gnu",
            "riscv64gc-unknown-linux-gnu",
            "s390x-unknown-linux-gnu",
            "sparc-unknown-linux-gnu",
            "sparc64-unknown-linux-gnu",
            // Linux (musl)
            "aarch64-unknown-linux-musl",
            "armv5te-unknown-linux-musleabi",
            "loongarch64-unknown-linux-musl",
            "mips-unknown-linux-musl",
            "mips64-unknown-linux-muslabi64",
            "mips64el-unknown-linux-muslabi64",
            "mipsel-unknown-linux-musl",
            // "mipsisa32r6-unknown-linux-musl", // TODO: not in rustc
            // "mipsisa32r6el-unknown-linux-musl", // TODO: not in rustc
            // "mipsisa64r6-unknown-linux-muslabi64", // TODO: not in rustc
            // "mipsisa64r6el-unknown-linux-muslabi64", // TODO: not in rustc
            "powerpc-unknown-linux-musl",
            "powerpc64-unknown-linux-musl",
            "powerpc64le-unknown-linux-musl",
            "riscv32gc-unknown-linux-musl",
            "riscv64gc-unknown-linux-musl",
            "s390x-unknown-linux-musl",
            // Linux (uClibc-ng)
            "aarch64-unknown-linux-uclibc",
            "armv5te-unknown-linux-uclibceabi",
            "mips-unknown-linux-uclibc",
            "mipsel-unknown-linux-uclibc",
            // "mipsisa32r6-unknown-linux-uclibc", // TODO: not in rustc
            // "mipsisa32r6el-unknown-linux-uclibc", // TODO: not in rustc
            "powerpc-unknown-linux-uclibc",
            // "riscv32gc-unknown-linux-uclibc", // TODO: not in rustc
            // "riscv64gc-unknown-linux-uclibc", // TODO: not in rustc
            "sparc-unknown-linux-uclibc",
            "sparc64-unknown-linux-uclibc",
            // L4Re (uClibc-ng)
            "aarch64-unknown-l4re-uclibc",
            // Android
            "aarch64-linux-android",
            "arm-linux-androideabi",
            "riscv64-linux-android",
        ],
        headers: &[
            Header {
                // https://github.com/torvalds/linux/blob/HEAD/arch/powerpc/include/uapi/asm/cputable.h
                path: "linux-headers:asm/cputable.h",
                types: &[],
                vars: &["PPC_FEATURE.*"],
                functions: &[],
                arch: &[powerpc, powerpc64],
                os: &[],
                env: &[],
            },
            Header {
                // https://github.com/torvalds/linux/blob/HEAD/arch/arm64/include/uapi/asm/hwcap.h
                // https://github.com/torvalds/linux/blob/HEAD/arch/arm/include/uapi/asm/hwcap.h
                // https://github.com/torvalds/linux/blob/HEAD/arch/loongarch/include/uapi/asm/hwcap.h
                // https://github.com/torvalds/linux/blob/HEAD/arch/mips/include/uapi/asm/hwcap.h
                // https://github.com/torvalds/linux/blob/HEAD/arch/riscv/include/uapi/asm/hwcap.h
                path: "linux-headers:asm/hwcap.h",
                types: &[],
                // TODO: COMPAT_HWCAP.* for riscv
                vars: &["HWCAP.*"],
                functions: &[],
                arch: &[aarch64, arm, loongarch64, mips, mips32r6, mips64, mips64r6, riscv32, riscv64],
                os: &[],
                env: &[],
            },
            Header {
                // https://github.com/torvalds/linux/blob/HEAD/arch/riscv/include/uapi/asm/hwprobe.h
                path: "linux-headers:asm/hwprobe.h",
                types: &["riscv_hwprobe"],
                vars: &["RISCV_HWPROBE_.*"],
                functions: &[],
                arch: &[riscv32, riscv64],
                os: &[],
                env: &[],
            },
            Header {
                path: "linux-headers:asm/unistd.h",
                types: &[],
                vars: &["__NR_.*"],
                functions: &[],
                arch: &[],
                os: &[],
                env: &[],
            },
            Header {
                // https://github.com/torvalds/linux/blob/HEAD/include/uapi/linux/auxvec.h
                path: "linux-headers:linux/auxvec.h",
                types: &[],
                vars: &["AT_.*"],
                functions: &[],
                arch: &[],
                os: &[],
                env: &[],
            },
            Header {
                // https://github.com/torvalds/linux/blob/HEAD/include/uapi/linux/prctl.h
                path: "linux-headers:linux/prctl.h",
                types: &[],
                vars: &["PR_.*"],
                functions: &[],
                arch: &[],
                os: &[],
                env: &[],
            },
            Header {
                // https://github.com/bminor/glibc/blob/HEAD/dlfcn/dlfcn.h
                // https://github.com/bminor/musl/blob/HEAD/include/dlfcn.h
                // https://github.com/wbx-github/uclibc-ng/blob/HEAD/include/dlfcn.h
                // https://github.com/kernkonzept/l4re-core/blob/HEAD/uclibc/lib/contrib/uclibc/include/dlfcn.h
                // https://github.com/aosp-mirror/platform_bionic/blob/HEAD/libc/include/dlfcn.h
                path: "dlfcn.h",
                types: &[],
                vars: &["RTLD_DEFAULT"],
                functions: &["dlsym"],
                arch: &[],
                os: &[],
                env: &[],
            },
            Header {
                // https://github.com/bminor/glibc/blob/HEAD/elf/elf.h
                // https://github.com/bminor/musl/blob/HEAD/include/elf.h
                // https://github.com/wbx-github/uclibc-ng/blob/HEAD/include/elf.h
                // https://github.com/kernkonzept/l4re-core/blob/HEAD/uclibc/lib/contrib/uclibc/include/elf.h
                // https://github.com/aosp-mirror/platform_bionic/blob/HEAD/libc/include/elf.h
                path: "elf.h",
                types: &["Elf.*_auxv_t"],
                vars: &[],
                functions: &[],
                arch: &[],
                os: &[],
                env: &[],
            },
            Header {
                // https://github.com/bminor/glibc/blob/HEAD/misc/sys/auxv.h
                // https://github.com/bminor/musl/blob/HEAD/include/sys/auxv.h
                // https://github.com/wbx-github/uclibc-ng/blob/HEAD/include/sys/auxv.h
                // https://github.com/kernkonzept/l4re-core/blob/HEAD/uclibc/lib/contrib/uclibc/include/sys/auxv.h
                // https://github.com/aosp-mirror/platform_bionic/blob/HEAD/libc/include/sys/auxv.h
                path: "sys/auxv.h",
                types: &[],
                // HWCAP_S390_.*/HWCAP_SPARC_.* are not exposed from uapi/asm/hwcap.h
                // https://github.com/torvalds/linux/blob/HEAD/arch/s390/include/asm/elf.h
                // https://github.com/bminor/glibc/blob/HEAD/sysdeps/unix/sysv/linux/s390/bits/hwcap.h
                // https://github.com/bminor/musl/blob/HEAD/arch/s390x/bits/hwcap.h
                // https://github.com/torvalds/linux/blob/HEAD/arch/sparc/include/asm/elf_32.h
                // https://github.com/torvalds/linux/blob/HEAD/arch/sparc/include/asm/elf_64.h
                // https://github.com/bminor/glibc/blob/HEAD/sysdeps/sparc/bits/hwcap.h
                vars: &["HWCAP[^_]*_S390_.*", "HWCAP[^_]*_SPARC_.*"],
                functions: &["getauxval"],
                arch: &[],
                os: &[],
                env: &[],
            },
            Header {
                // https://github.com/aosp-mirror/platform_bionic/blob/HEAD/libc/include/sys/system_properties.h
                path: "sys/system_properties.h",
                types: &[],
                vars: &["PROP_VALUE_MAX"],
                functions: &["__system_property_get"],
                arch: &[aarch64],
                os: &[android],
                env: &[],
            },
            Header {
                path: "unistd.h",
                types: &[],
                vars: &[],
                functions: &["syscall"],
                arch: &[],
                os: &[],
                env: &[],
            },
        ],
    },
    Target {
        triples: &[
            "aarch64-apple-darwin",
            "aarch64-apple-ios",
            "aarch64-apple-tvos",
            "aarch64-apple-visionos",
            "aarch64-apple-watchos",
            "arm64_32-apple-watchos",
            // "armv7k-apple-watchos",
            // "armv7s-apple-ios",
        ],
        headers: &[
            Header {
                // https://github.com/apple-oss-distributions/xnu/blob/HEAD/bsd/sys/sysctl.h
                path: "sys/sysctl.h",
                types: &[],
                vars: &["CTL_MAXNAME"],
                functions: &["sysctlbyname"],
                arch: &[],
                os: &[],
                env: &[],
            },
        ],
    },
    Target {
        triples: &[
            "aarch64-unknown-freebsd",
            "armv6-unknown-freebsd",
            "powerpc-unknown-freebsd",
            "powerpc64-unknown-freebsd",
            "powerpc64le-unknown-freebsd",
            "riscv64gc-unknown-freebsd",
        ],
        headers: &[
            Header {
                // https://github.com/freebsd/freebsd-src/blob/HEAD/include/dlfcn.h
                path: "dlfcn.h",
                types: &[],
                vars: &["RTLD_DEFAULT"],
                functions: &["dlsym"],
                arch: &[],
                os: &[],
                env: &[],
            },
            Header {
                // https://github.com/freebsd/freebsd-src/blob/HEAD/sys/sys/auxv.h
                path: "sys/auxv.h",
                types: &[],
                vars: &[],
                functions: &["elf_aux_info"],
                arch: &[],
                os: &[],
                env: &[],
            },
            Header {
                // https://github.com/freebsd/freebsd-src/blob/HEAD/sys/sys/syscall.h
                path: "sys/syscall.h",
                types: &[],
                vars: &["SYS_.*"],
                functions: &[],
                arch: &[],
                os: &[],
                env: &[],
            },
            Header {
                // https://github.com/freebsd/freebsd-src/blob/HEAD/sys/sys/sysctl.h
                path: "sys/sysctl.h",
                types: &[],
                vars: &["CTL_KERN", "KERN_PROC", "KERN_PROC_AUXV"],
                functions: &[],
                arch: &[],
                os: &[],
                env: &[],
            },
            Header {
                // https://github.com/freebsd/freebsd-src/blob/HEAD/sys/sys/elf_common.h
                path: "sys/elf_common.h",
                types: &[],
                vars: &["AT_.*"],
                functions: &[],
                arch: &[],
                os: &[],
                env: &[],
            },
            Header {
                // https://github.com/freebsd/freebsd-src/blob/HEAD/sys/powerpc/include/cpu.h
                path: "machine/cpu.h",
                types: &[],
                vars: &["PPC_FEATURE.*"],
                functions: &[],
                arch: &[powerpc, powerpc64],
                os: &[],
                env: &[],
            },
            Header {
                // https://github.com/freebsd/freebsd-src/blob/HEAD/sys/arm64/include/elf.h
                // https://github.com/freebsd/freebsd-src/blob/HEAD/sys/arm/include/elf.h
                // https://github.com/freebsd/freebsd-src/blob/HEAD/sys/powerpc/include/elf.h
                // https://github.com/freebsd/freebsd-src/blob/HEAD/sys/riscv/include/elf.h
                path: "machine/elf.h",
                types: &["Elf.*_Auxinfo"],
                vars: &["HWCAP.*"],
                functions: &[],
                // TODO: riscv
                arch: &[aarch64, arm, powerpc, powerpc64],
                os: &[],
                env: &[],
            },
        ],
    },
    Target {
        triples: &[
            "aarch64-unknown-netbsd",
            "aarch64_be-unknown-netbsd",
            "armv6-unknown-netbsd-eabihf",
            "armebv6-unknown-netbsd-eabihf",
            // "mips-unknown-netbsd", // TODO: not in rustc
            "mipsel-unknown-netbsd",
            // "mips64-unknown-netbsd", // TODO: not in rustc
            // "mips64el-unknown-netbsd", // TODO: not in rustc https://github.com/NetBSD/pkgsrc/blob/c57db65bc56140bd6176f5b95e0af10461a483c8/lang/rust/patches/patch-compiler_rustc__target_src_spec_targets_mips64el__unknown__netbsd.rs is n32 ABI...
            "powerpc-unknown-netbsd",
            "powerpc64-unknown-netbsd",
            // "riscv64gc-unknown-netbsd",
            "sparc-unknown-netbsd",
            "sparc64-unknown-netbsd",
        ],
        headers: &[
            Header {
                // https://github.com/NetBSD/src/blob/HEAD/sys/sys/syscall.h
                path: "sys/syscall.h",
                types: &[],
                vars: &["SYS_.*"],
                functions: &[],
                arch: &[],
                os: &[],
                env: &[],
            },
            Header {
                // https://github.com/NetBSD/src/blob/HEAD/sys/sys/sysctl.h
                path: "sys/sysctl.h",
                types: &["sysctlnode"],
                vars: &["CTL_MACHDEP", "CTL_QUERY", "SYSCTL_VERS_1", "SYSCTL_VERSION"],
                functions: &["sysctl", "sysctlbyname"],
                arch: &[],
                os: &[],
                env: &[],
            },
            Header {
                // https://github.com/NetBSD/src/blob/HEAD/sys/arch/aarch64/include/armreg.h
                path: "machine/armreg.h",
                types: &["aarch64_sysctl_cpu_id"],
                vars: &[],
                functions: &[],
                arch: &[aarch64],
                os: &[],
                env: &[],
            },
            Header {
                // https://github.com/NetBSD/src/blob/HEAD/sys/arch/aarch64/include/cpu.h
                // https://github.com/NetBSD/src/blob/HEAD/sys/arch/arm/include/cpu.h
                // https://github.com/NetBSD/src/blob/HEAD/sys/arch/mips/include/cpu.h
                // https://github.com/NetBSD/src/blob/HEAD/sys/arch/powerpc/include/cpu.h
                // https://github.com/NetBSD/src/blob/HEAD/sys/arch/riscv/include/cpu.h
                // https://github.com/NetBSD/src/blob/HEAD/sys/arch/sparc/include/cpu.h
                // https://github.com/NetBSD/src/blob/HEAD/sys/arch/sparc64/include/cpu.h
                path: "machine/cpu.h",
                types: &[],
                vars: &["CPU_.*"],
                functions: &[],
                arch: &[],
                os: &[],
                env: &[],
            },
        ],
    },
    Target {
        triples: &[
            "aarch64-unknown-openbsd",
            "armv7-unknown-openbsd",
            // "mips64-unknown-openbsd", // TODO: not in rustc
            // "mips64el-unknown-openbsd", // TODO: not in rustc
            "powerpc-unknown-openbsd",
            "powerpc64-unknown-openbsd",
            "riscv64gc-unknown-openbsd",
            "sparc64-unknown-openbsd",
        ],
        headers: &[
            Header {
                // https://github.com/openbsd/src/blob/HEAD/include/dlfcn.h
                path: "dlfcn.h",
                types: &[],
                vars: &["RTLD_DEFAULT"],
                functions: &["dlsym"],
                arch: &[],
                os: &[],
                env: &[],
            },
            Header {
                // https://github.com/openbsd/src/blob/HEAD/sys/sys/auxv.h
                path: "sys/auxv.h",
                types: &[],
                vars: &["AT_.*"],
                functions: &["elf_aux_info"],
                arch: &[],
                os: &[],
                env: &[],
            },
            Header {
                // https://github.com/openbsd/src/blob/HEAD/sys/sys/sysctl.h
                path: "sys/sysctl.h",
                types: &[],
                vars: &["CTL_MACHDEP"],
                functions: &["sysctl"],
                arch: &[],
                os: &[],
                env: &[],
            },
            Header {
                // https://github.com/openbsd/src/blob/HEAD/sys/arch/arm64/include/cpu.h
                // https://github.com/openbsd/src/blob/HEAD/sys/arch/arm/include/cpu.h
                // https://github.com/openbsd/src/blob/HEAD/sys/arch/mips64/include/cpu.h
                // https://github.com/openbsd/src/blob/HEAD/sys/arch/macppc/include/cpu.h
                // https://github.com/openbsd/src/blob/HEAD/sys/arch/powerpc64/include/cpu.h
                // https://github.com/openbsd/src/blob/HEAD/sys/arch/riscv64/include/cpu.h
                // https://github.com/openbsd/src/blob/HEAD/sys/arch/sparc64/include/cpu.h
                path: "machine/cpu.h",
                types: &[],
                vars: &["CPU_.*"],
                functions: &[],
                arch: &[],
                os: &[],
                env: &[],
            },
            Header {
                // https://github.com/openbsd/src/blob/HEAD/sys/arch/arm64/include/elf.h
                // https://github.com/openbsd/src/blob/HEAD/sys/arch/arm/include/elf.h
                // https://github.com/openbsd/src/blob/HEAD/sys/arch/mips64/include/elf.h
                // https://github.com/openbsd/src/blob/HEAD/sys/arch/powerpc/include/elf.h
                // https://github.com/openbsd/src/blob/HEAD/sys/arch/powerpc64/include/elf.h
                // https://github.com/openbsd/src/blob/HEAD/sys/arch/riscv64/include/elf.h
                // https://github.com/openbsd/src/blob/HEAD/sys/arch/sparc64/include/elf.h
                path: "machine/elf.h",
                types: &[],
                vars: &["HWCAP.*", "PPC_FEATURE.*"],
                functions: &[],
                // TODO: riscv
                arch: &[aarch64, arm, mips64, mips64r6, powerpc, powerpc64, sparc64],
                os: &[],
                env: &[],
            },
        ],
    },
    Target {
        triples: &[
            "sparcv9-sun-solaris",
            "aarch64-unknown-illumos",
        ],
        headers: &[
            Header {
                // https://github.com/illumos/illumos-gate/blob/HEAD/usr/src/uts/common/sys/auxv.h
                // https://github.com/richlowe/illumos-gate/blob/arm64-gate/usr/src/uts/common/sys/auxv.h
                // https://github.com/richlowe/illumos-gate/blob/arm64-gate/usr/src/uts/common/sys/auxv_aarch64.h
                // https://github.com/illumos/illumos-gate/blob/HEAD/usr/src/uts/common/sys/auxv_SPARC.h
                path: "sys/auxv.h",
                types: &[],
                vars: &["AV.*"],
                functions: &["getisax"],
                arch: &[],
                os: &[],
                env: &[],
            },
        ],
    },
    Target {
        triples: &[
            "powerpc64-ibm-aix",
        ],
        // TODO: There is no way to access to AIX headers.
        headers: &[],
    },
    Target {
        triples: &[
            "aarch64-unknown-fuchsia",
            "riscv64gc-unknown-fuchsia",
        ],
        headers: &[
            // TODO: zx_system_get_features
            Header {
                // https://fuchsia.googlesource.com/fuchsia/+/refs/heads/main/zircon/system/public/zircon/types.h
                path: "zircon/system/public/zircon/types.h",
                types: &["zx_status_t"],
                vars: &[],
                functions: &[],
                arch: &[],
                os: &[],
                env: &[],
            },
            Header {
                // https://fuchsia.googlesource.com/fuchsia/+/refs/heads/main/zircon/system/public/zircon/errors.h
                path: "zircon/system/public/zircon/errors.h",
                types: &[],
                vars: &["ZX_OK"],
                functions: &[],
                arch: &[],
                os: &[],
                env: &[],
            },
            Header {
                // https://fuchsia.googlesource.com/fuchsia/+/refs/heads/main/zircon/system/public/zircon/features.h
                path: "zircon/system/public/zircon/features.h",
                types: &[],
                vars: &["ZX_.*"],
                functions: &[],
                arch: &[],
                os: &[],
                env: &[],
            },
        ],
    },
];

#[derive(Clone, Copy)]
struct Target {
    triples: &'static [&'static str],
    headers: &'static [Header],
}

#[derive(Clone, Copy)]
struct Header {
    path: &'static str,
    types: &'static [&'static str],
    vars: &'static [&'static str],
    functions: &'static [&'static str],

    // If not empty, code is generated only for the specified targets.
    arch: &'static [Arch],
    os: &'static [Os],
    env: &'static [Env],
}

pub(crate) fn generate() {
    if !cfg!(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"))) {
        eprintln!("warning: codegen is only fully supported on x86_64/aarch64 Linux");
        // TODO
        return;
    }
    let workspace_root = &workspace_root();
    let download_dir = &workspace_root.join("tools/codegen/tmp/cache");
    fs::create_dir_all(download_dir).unwrap();
    let out_dir = &workspace_root.join("src/gen/sys");
    if out_dir.exists() {
        // TODO
        fs::remove_dir_all(out_dir).unwrap();
    }
    let raw_line = file::header(function_name!());
    let raw_line = raw_line.trim_end();

    let mut target_modules = vec![];
    for &Target { triples, headers } in TARGETS {
        for &triple in triples {
            eprintln!("\ninfo: generating bindings for {triple}");
            let target = &target_spec_json(triple);
            let mut module_name = triple
                .replace(&*format!("-{}-", target.vendor.as_deref().unwrap_or("unknown")), "-")
                .replace(['-', '.'], "_");
            if target.arch.as_str().starts_with("riscv") {
                module_name = module_name
                    .replace(&*format!("{}gc", target.arch.as_str()), target.arch.as_str());
            }
            let out_dir = &out_dir.join(&module_name);
            {
                let module_name = format_ident!("{}", module_name);
                let mut cfg = quote!();
                let arch = target.arch.as_str();
                cfg.extend(quote! { target_arch = #arch });
                let os = target.os.as_str();
                cfg.extend(quote! { , target_os = #os });
                if target.env != Env::none {
                    let env = target.env.as_str();
                    cfg.extend(quote! { , target_env = #env });
                }
                let endian = target.target_endian.as_str();
                cfg.extend(quote! { , target_endian = #endian });
                let width = &target.target_pointer_width;
                cfg.extend(quote! { , target_pointer_width = #width });
                target_modules.push(quote! {
                    #[cfg(all(#cfg))]
                    mod #module_name;
                    #[cfg(all(#cfg))]
                    pub use self::#module_name::*;
                });
            }
            fs::create_dir_all(out_dir).unwrap();

            let mut modules = vec![];
            let mut first = true;
            let mut src_dir = Utf8PathBuf::new();
            let mut files = vec![];
            for &header in headers {
                if !header.arch.is_empty() && !header.arch.contains(&target.arch) {
                    continue;
                }
                if !header.os.is_empty() && !header.os.contains(&target.os) {
                    continue;
                }
                if !header.env.is_empty() && !header.env.contains(&target.env) {
                    continue;
                }
                if target.os == linux
                    && target.env == gnu
                    && target.arch == aarch64
                    && target.target_pointer_width == "32"
                    && matches!(header.path, "sys/rseq.h")
                {
                    // TODO: ilp32 fork is old
                    continue;
                }
                if first {
                    src_dir = download_headers(target, download_dir);
                    first = false;
                }
                let src_dir = &src_dir;

                let functions = header.functions.join("|");
                let types = header.types.join("|");
                let vars = header.vars.join("|");

                let out_file = format!(
                    "{}.rs",
                    Utf8PathBuf::from(header.path.replace(['/', '-', ':'], "_"))
                        .file_stem()
                        .unwrap()
                );
                let out_path = out_dir.join(&out_file);

                let target_flag = &*format!("--target={}", target.llvm_target);
                let mut clang_args = vec![target_flag, "-nostdinc"];
                macro_rules! define {
                    ($name:ident) => {{
                        clang_args.push(concat!("-D", stringify!($name)));
                    }};
                    ($name:ident, $value:literal) => {{
                        clang_args.push(concat!("-D", stringify!($name), "=", $value));
                    }};
                }
                macro_rules! include_header {
                    ($value:literal) => {{
                        clang_args.push(concat!("-include", $value));
                    }};
                }
                let header_path;
                let include;
                match target.os {
                    linux | l4re | android => {
                        let linux_headers_dir = linux_headers_dir(target, src_dir);
                        if let Some(path) = header.path.strip_prefix("linux-headers:") {
                            header_path = linux_headers_dir.join("include").join(path);
                            include = vec![linux_headers_dir.join("include")];
                        } else if target.os == android {
                            let bionic_dir = bionic_dir(src_dir).join("libc");
                            header_path = bionic_dir.join("include").join(header.path);
                            include = vec![
                                bionic_dir.join("include"),
                                bionic_dir.join("kernel/uapi"),
                                bionic_dir.join("kernel/android/uapi"),
                            ];
                        } else if target.os == l4re {
                            let arch = l4re_arch(target);
                            let libc_dir = src_dir.join("../../headers/l4re").join(arch);
                            header_path = libc_dir.join("usr/include").join(header.path);
                            include = vec![
                                libc_dir.join("usr/include/l4-arch"),
                                libc_dir.join("usr/include"),
                            ];
                        } else {
                            let headers_dir = libc_headers_dir(target, src_dir);
                            header_path = headers_dir.join("include").join(header.path);
                            include = vec![
                                headers_dir.join("include"),
                                linux_headers_dir.join("include"),
                            ];
                        }
                        define!(_GNU_SOURCE);
                    }
                    _ if target.vendor.as_deref() == Some("apple") => {
                        header_path = src_dir.join("bsd").join(header.path);
                        include = vec![
                            src_dir.join("bsd"),
                            src_dir.join("EXTERNAL_HEADERS"),
                            src_dir.join("osfmk"),
                            src_dir.parent().unwrap().join("Libc/include"),
                            src_dir.parent().unwrap().join("libpthread/include"),
                        ];
                        // https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/sys/cdefs.h#L628-L638
                        define!(_POSIX_C_SOURCE, "200112L");
                        include_header!("sys/_types/_u_char.h");
                        include_header!("sys/_types/_u_short.h");
                        include_header!("sys/_types/_u_int.h");
                    }
                    freebsd | openbsd => {
                        header_path = src_dir.join("include").join(header.path);
                        include = vec![src_dir.join("include")];
                        include_header!("sys/types.h");
                    }
                    netbsd => {
                        header_path = src_dir.join("include").join(header.path);
                        include = vec![
                            src_dir.join("include"),
                            src_dir.join("include/sys"),
                            src_dir.join("lib/libpthread"),
                        ];
                        match target.arch {
                            mips | mips32r6 | mips64 | mips64r6 => match target.target_endian {
                                little => define!(_BYTE_ORDER, "_LITTLE_ENDIAN"),
                                big => define!(_BYTE_ORDER, "_BIG_ENDIAN"),
                            },
                            _ => {}
                        }
                    }
                    solaris => {
                        header_path = src_dir.join("usr/include").join(header.path);
                        include = vec![src_dir.join("usr/include")];
                    }
                    illumos => {
                        header_path = src_dir.join("usr/src/uts/common").join(header.path);
                        include = vec![
                            src_dir.join("usr/src/uts/common"),
                            src_dir.join("usr/src/uts").join(illumos_arch(target)),
                            src_dir.join("usr/src/head"),
                        ];
                    }
                    fuchsia => {
                        header_path = src_dir.join(header.path);
                        include = vec![
                            src_dir.join("zircon/system/public"),
                            src_dir.join("zircon/kernel/lib/libc/include"),
                        ];
                        define!(_KERNEL); // TODO: rm?
                    }
                    _ => todo!("{target:?}"),
                }
                for include in &include {
                    clang_args.push("-I");
                    clang_args.push(include.as_str());
                }

                let bindings = bindgen::builder()
                    .array_pointers_in_arguments(true)
                    .derive_debug(false)
                    .disable_header_comment()
                    .generate_comments(false)
                    .layout_tests(false)
                    .rust_target(bindgen::RustTarget::Stable_1_36)
                    .use_core()
                    .formatter(bindgen::Formatter::Prettyplease)
                    .header(header_path.as_str())
                    .clang_args(&clang_args)
                    .allowlist_function(&functions)
                    .allowlist_type(&types)
                    .allowlist_var(&vars)
                    .raw_line(raw_line)
                    .generate()
                    .unwrap_or_else(|e| panic!("failed to generate for {}: {}", header.path, e));
                bindings.write_to_file(out_path).unwrap_or_else(|e| {
                    panic!("failed to write_to_file for {}: {}", header.path, e)
                });

                files.push((out_file, functions, types, vars));
            }
            for (path, functions, types, vars) in &files {
                let module_name = format_ident!("{}", Utf8Path::new(path).file_stem().unwrap());
                let mut uses = vec![];
                // Only export matched names because the module may contain type def.
                let functions = Regex::new(&format!("^({functions})$")).unwrap();
                let types = Regex::new(&format!("^({types})$")).unwrap();
                let vars = Regex::new(&format!("^({vars})$")).unwrap();
                let f = syn::parse_file(&fs::read_to_string(out_dir.join(path)).unwrap()).unwrap();
                for i in f.items {
                    match i {
                        syn::Item::ForeignMod(i) => {
                            for i in i.items {
                                match i {
                                    syn::ForeignItem::Fn(i)
                                        if matches!(i.vis, syn::Visibility::Public(..))
                                            && functions.is_match(&i.sig.ident.to_string()) =>
                                    {
                                        uses.push(format_ident!("{}", i.sig.ident));
                                    }
                                    syn::ForeignItem::Static(i)
                                        if matches!(i.vis, syn::Visibility::Public(..))
                                            && vars.is_match(&i.ident.to_string()) =>
                                    {
                                        uses.push(format_ident!("{}", i.ident));
                                    }
                                    _ => {}
                                }
                            }
                        }
                        syn::Item::Struct(syn::ItemStruct { vis, ident, .. })
                        | syn::Item::Type(syn::ItemType { vis, ident, .. })
                            if matches!(vis, syn::Visibility::Public(..))
                                && types.is_match(&ident.to_string()) =>
                        {
                            uses.push(format_ident!("{ident}"));
                        }
                        syn::Item::Const(i)
                            if matches!(i.vis, syn::Visibility::Public(..))
                                && vars.is_match(&i.ident.to_string()) =>
                        {
                            uses.push(format_ident!("{}", i.ident));
                        }
                        _ => {}
                    }
                }
                let uses = uses.iter();
                modules.push(quote! {
                    mod #module_name;
                    #(pub use self::#module_name::#uses;)*
                });
            }
            // e.g., clang -E -dM -x c /dev/null -target aarch64-unknown-linux-gnu | grep -F __CHAR_
            let clang_defs =
                cmd!("clang", "-E", "-dM", "-x", "c", "/dev/null", "-target", &target.llvm_target)
                    .read()
                    .unwrap();
            let c_char_type = if clang_defs.lines().any(|l| l == "#define __CHAR_UNSIGNED__ 1") {
                quote! { u8 }
            } else {
                quote! { i8 }
            };
            file::write(function_name!(), out_dir.join("mod.rs"), quote! {
                #(#modules)*
                pub type c_char = #c_char_type;
            })
            .unwrap();
        }
    }
    file::write(function_name!(), out_dir.join("mod.rs"), quote! {
        #![allow(
            dead_code,
            non_camel_case_types,
            non_upper_case_globals,
            unreachable_pub,
            unknown_lints,
            unnameable_types, // unnameable_types is available on Rust 1.79+
            clippy::cast_sign_loss,
            clippy::ptr_as_ptr,
            clippy::pub_underscore_fields,
            clippy::unnecessary_cast,
        )]
        #(#target_modules)*
    })
    .unwrap();
}

// https://github.com/bminor/glibc
const GLIBC_REPO: &str = "bminor/glibc";
// https://github.com/bminor/musl
const MUSL_REPO: &str = "bminor/musl";
// https://github.com/wbx-github/uclibc-ng
const UCLIBC_REPO: &str = "wbx-github/uclibc-ng";
// https://github.com/aosp-mirror/platform_bionic
const BIONIC_REPO: &str = "aosp-mirror/platform_bionic";
fn download_headers(target: &TargetSpec, download_dir: &Utf8Path) -> Utf8PathBuf {
    #[track_caller]
    fn clone(
        download_dir: &Utf8Path,
        repository: &str,
        branch: Option<&str>,
        sparse_checkout: &[&str],
    ) -> Utf8PathBuf {
        let name = repository.strip_suffix(".git").unwrap_or(repository);
        let name = name.replace("https://fuchsia.googlesource.com/", "fuchsia/");
        let name = name.replace("https://git.linaro.org/toolchain/", "linaro-toolchain/");
        let name =
            name.replace("https://git.kernel.org/pub/scm/linux/kernel/git/arm64/", "linux-arm64/");
        assert!(!name.contains("://"), "{}", name);
        let repository = if repository.contains("://") {
            repository.to_owned()
        } else {
            format!("https://github.com/{repository}.git")
        };
        let src_dir = download_dir.join(name);
        if !src_dir.exists() {
            fs::create_dir_all(src_dir.parent().unwrap()).unwrap();
            if sparse_checkout.is_empty() {
                if let Some(branch) = branch {
                    cmd!("git", "clone", "--depth", "1", "-b", branch, repository, &src_dir)
                        .run()
                        .unwrap();
                } else {
                    cmd!("git", "clone", "--depth", "1", repository, &src_dir).run().unwrap();
                }
            } else {
                if let Some(branch) = branch {
                    cmd!(
                        "git",
                        "clone",
                        "--depth",
                        "1",
                        "--filter=tree:0",
                        "--no-checkout",
                        "-b",
                        branch,
                        repository,
                        &src_dir,
                    )
                    .run()
                    .unwrap();
                } else {
                    cmd!(
                        "git",
                        "clone",
                        "--depth",
                        "1",
                        "--filter=tree:0",
                        "--no-checkout",
                        repository,
                        &src_dir,
                    )
                    .run()
                    .unwrap();
                }
            }
        }
        if sparse_checkout.is_empty() {
            if let Some(branch) = branch {
                cmd!("git", "checkout", branch).dir(&src_dir).stdout_capture().run().unwrap();
            }
        } else {
            let _ = fs::remove_file(src_dir.join(".git").join("index.lock"));
            cmd!("git", "sparse-checkout", "init").dir(&src_dir).run().unwrap();
            let mut out = String::from("/*\n!/*/\n"); // always download top-level files
            out.push_str(&sparse_checkout.join("\n"));
            fs::write(src_dir.join(".git/info/sparse-checkout"), out).unwrap();
            cmd!("git", "checkout").dir(&src_dir).stdout_capture().run().unwrap();
        }
        cmd!("git", "clean", "-df").dir(&src_dir).stdout_capture().run().unwrap();
        let _ = fs::remove_file(src_dir.join(".git").join("index.lock"));
        cmd!("git", "checkout", ".").dir(&src_dir).stderr_capture().run().unwrap();
        src_dir
    }
    #[track_caller]
    fn curl(
        download_dir: &Utf8Path,
        name: &str,
        url: &str,
        paths: &str,
        strip_components: &str,
    ) -> Utf8PathBuf {
        let src_dir = download_dir.join(name);
        if src_dir.exists() {
            return src_dir;
        }
        let file = &download_dir.join(Utf8Path::new(url).file_name().unwrap());
        if !file.exists() {
            cmd!(
                "curl",
                "--proto",
                "=https",
                "--tlsv1.2",
                "-fsSL",
                "--retry",
                "10",
                "--retry-connrefused",
                url,
                "-o",
                file
            )
            .run()
            .unwrap();
        }
        fs::create_dir_all(&src_dir).unwrap();
        if file.extension() == Some("deb") {
            assert_eq!(strip_components, "0");
            assert_eq!(paths, "");
            cmd!("dpkg-deb", "-x", file, &src_dir).run().unwrap();
        } else {
            cmd!("tar", "xf", file, "--strip-components", strip_components, "-C", &src_dir, paths)
                .run()
                .unwrap();
        }
        src_dir
    }
    #[track_caller]
    fn patch(target: &TargetSpec, src_dir: &Utf8Path) {
        let patch_dir = workspace_root().join("tools/codegen/patches");
        for path in [
            patch_dir.join(format!("{}.diff", target.os)),
            patch_dir.join(format!("{}-{}.diff", target.os, target.env)),
        ] {
            if !path.exists() {
                continue;
            }
            let dir = match target.os {
                linux => {
                    if target.env == gnu {
                        if target.arch == aarch64 && target.target_pointer_width == "32" {
                            return;
                        }
                        glibc_dir(target, src_dir)
                    } else {
                        todo!("{target:?}")
                    }
                }
                android => bionic_dir(src_dir),
                _ => src_dir.to_owned(),
            };
            cmd!("patch", "-p1")
                .stdin_file(fs::File::open(path).unwrap().into_parts().0) // TODO: Buffering?
                .dir(dir)
                .run()
                .unwrap();
        }
    }

    let src_dir;
    let mut patched = false;
    match target.os {
        linux | l4re | android => {
            src_dir = if target.arch == aarch64 && target.target_pointer_width == "32" {
                clone(
                    download_dir,
                    "https://git.kernel.org/pub/scm/linux/kernel/git/arm64/linux.git",
                    Some("staging/ilp32-5.1"),
                    &[],
                )
            } else {
                clone(download_dir, "torvalds/linux", None, &[
                    "/arch/",
                    "/include/",
                    "/scripts/",
                    "/tools/",
                ])
            };
            let linux_arch = linux_arch(target);
            let linux_headers_dir = &linux_headers_dir(target, &src_dir);
            if !linux_headers_dir.exists() {
                // https://github.com/torvalds/linux/blob/HEAD/Documentation/kbuild/headers_install.rst
                cmd!(
                    "make",
                    "headers_install",
                    format!("ARCH={linux_arch}"),
                    format!("INSTALL_HDR_PATH={linux_headers_dir}"),
                )
                .dir(&src_dir)
                .stdout_capture()
                .run()
                .unwrap();
            }
            if target.os == android {
                clone(download_dir, BIONIC_REPO, None, &["/libc/"]);
                let bionic_dir = bionic_dir(&src_dir);
                let asm_arch = match target.arch {
                    arm => "asm-arm",
                    aarch64 => "asm-arm64",
                    riscv32 | riscv64 => "asm-riscv",
                    x86 | x86_64 => "asm-x86",
                    _ => todo!("{target:?}"),
                };
                symlink(
                    bionic_dir.join("libc/kernel/uapi").join(asm_arch).join("asm"),
                    bionic_dir.join("libc/kernel/uapi").join("asm"),
                )
                .unwrap();
                fs::write(
                    bionic_dir.join("libc/include/stddef.h"),
                    "\
                    typedef __SIZE_TYPE__ size_t;\n\
                    typedef __PTRDIFF_TYPE__ ptrdiff_t;\n\
                    ",
                )
                .unwrap();
                fs::write(bionic_dir.join("libc/include/stdbool.h"), "#define bool _Bool\n")
                    .unwrap();
                fs::write(bionic_dir.join("libc/include/float.h"), "").unwrap();
            } else if target.os == l4re {
                // https://os.inf.tu-dresden.de/download/snapshots/toolchain/
                let gcc_version = "14";
                let arch = l4re_arch(target);
                let name = &format!("headers/l4re/{arch}");
                let headers_dir = download_dir.join(name);
                if !headers_dir.exists() {
                    curl(
                        download_dir,
                        name,
                        &format!(
                            "https://os.inf.tu-dresden.de/download/snapshots/toolchain/toolchain-l4re-{arch}-gcc-{gcc_version}.tar.xz",
                        ),
                        &format!("./sysroots/{}-l4re/usr/include", target.arch),
                        "3",
                    );
                }
                fs::write(
                    headers_dir.join("usr/include/stddef.h"),
                    "\
                    typedef __SIZE_TYPE__ size_t;\n\
                    typedef __WCHAR_TYPE__ wchar_t;\n\
                    ",
                )
                .unwrap();
                patched = true;
            } else if target.env == gnu {
                if target.arch == aarch64 && target.target_pointer_width == "32" {
                    clone(
                        download_dir,
                        "https://git.linaro.org/toolchain/glibc.git",
                        Some("arm/ilp32"),
                        &[],
                    );
                } else {
                    clone(download_dir, GLIBC_REPO, None, &[]);
                }
                let glibc_src_dir = &glibc_dir(target, &src_dir);
                let headers_dir = &libc_headers_dir(target, &src_dir);
                if !headers_dir.exists() {
                    let (cc, cflags) = linux_gcc(target);
                    // https://github.com/bminor/glibc/blob/HEAD/INSTALL
                    let build_dir = &glibc_src_dir.parent().unwrap().join("glibc-build");
                    if build_dir.exists() {
                        fs::remove_dir_all(build_dir).unwrap();
                    }
                    // /bin/sh: 1: cannot create /home/runner/work/test-helper/test-helper/tools/codegen/tmp/cache/bminor/glibc-build/elf/dso-sort-tests-all4.def: Directory nonexistent
                    fs::create_dir_all(build_dir.join("elf")).unwrap();
                    cmd!(
                        "bash",
                        "../glibc/configure",
                        format!("--prefix={headers_dir}"),
                        format!("--with-headers={linux_headers_dir}/include"),
                        format!("--build={}", target.llvm_target),
                        format!("--host={}", target.llvm_target),
                    )
                    .dir(build_dir)
                    .env("CC", format!("{cc}{cflags}"))
                    .run()
                    .unwrap();
                    cmd!("make", "install-headers").dir(build_dir).stdout_capture().run().unwrap();
                    fs::write(headers_dir.join("include/gnu/stubs.h"), "").unwrap();
                }
                fs::write(
                    headers_dir.join("include/stddef.h"),
                    "\
                    #define NULL ((void*)0)\n\
                    typedef __SIZE_TYPE__ size_t;\n\
                    typedef __PTRDIFF_TYPE__ ptrdiff_t;\n\
                    ",
                )
                .unwrap();
                patched = true;
            } else if target.env == musl {
                let musl_src_dir = &if target.arch == hexagon {
                    // https://github.com/quic/musl/tree/hexagon
                    clone(download_dir, "quic/musl", Some("hexagon"), &[]);
                    src_dir.join("../..").join("quic/musl")
                } else {
                    clone(download_dir, MUSL_REPO, None, &["/arch/", "/include/", "/tools/"]);
                    src_dir.join("../..").join(MUSL_REPO)
                };
                let musl_arch = musl_arch(target);
                let headers_dir = &libc_headers_dir(target, &src_dir);
                if !headers_dir.exists() {
                    // https://github.com/bminor/musl/blob/HEAD/Makefile
                    cmd!(
                        "make",
                        "install-headers",
                        format!("ARCH={musl_arch}"),
                        format!("DESTDIR={headers_dir}"),
                        "prefix=/",
                    )
                    .dir(musl_src_dir)
                    .stdout_capture()
                    .run()
                    .unwrap();
                }
                patched = true;
            } else if target.env == uclibc {
                clone(download_dir, UCLIBC_REPO, None, &[]);
                let uclibc_arch = uclibc_arch(target);
                let uclibc_src_dir = &src_dir.join("../..").join(UCLIBC_REPO);
                let config_path = &uclibc_src_dir.join(".config");
                if config_path.exists() {
                    fs::remove_file(config_path).unwrap();
                }
                let headers_dir = &libc_headers_dir(target, &src_dir);
                if !headers_dir.exists() {
                    let (cc, cflags) = linux_gcc(target);
                    // https://github.com/wbx-github/uclibc-ng/blob/HEAD/Makefile.in
                    cmd!(
                        "make",
                        "allnoconfig",
                        format!("ARCH={uclibc_arch}"),
                        "UCLIBC_HAS_REALTIME=y",
                        "UCLIBC_LINUX_SPECIFIC=y",
                    )
                    .dir(uclibc_src_dir)
                    .stdout_capture()
                    .run()
                    .unwrap();
                    cmd!(
                        "make",
                        "install_headers",
                        format!("ARCH={uclibc_arch}"),
                        "UCLIBC_HAS_REALTIME=y",
                        "UCLIBC_LINUX_SPECIFIC=y",
                        "HAVE_SHARED=y",
                        format!("DESTDIR={headers_dir}"),
                        format!("PREFIX={headers_dir}"),
                        "DEVEL_PREFIX=/",
                        format!("KERNEL_HEADERS={linux_headers_dir}/include"),
                        format!("CC={cc}{cflags}"),
                    )
                    .dir(uclibc_src_dir)
                    .stdout_capture()
                    .run()
                    .unwrap();
                }
                fs::write(
                    headers_dir.join("include/stddef.h"),
                    "\
                    typedef __SIZE_TYPE__ size_t;\n\
                    ",
                )
                .unwrap();
                patched = true;
            }
        }
        _ if target.vendor.as_deref() == Some("apple") => {
            clone(download_dir, "apple-oss-distributions/Libc", None, &["/include/"]);
            clone(download_dir, "apple-oss-distributions/libpthread", None, &["/include/"]);
            src_dir = clone(download_dir, "apple-oss-distributions/xnu", None, &[
                "/bsd/",
                "/EXTERNAL_HEADERS/",
                "/osfmk/",
            ]);
            // TODO: use https://github.com/apple-oss-distributions/xnu/blob/HEAD/Makefile?
            // https://github.com/apple-oss-distributions/xnu/blob/HEAD/bsd/sys/make_symbol_aliasing.sh
            fs::write(src_dir.join("bsd/sys/_symbol_aliasing.h"), "").unwrap();
            // https://github.com/apple-oss-distributions/xnu/blob/HEAD/bsd/sys/make_posix_availability.sh
            cmd!("bash", "bsd/sys/make_posix_availability.sh", "bsd/sys/_posix_availability.h")
                .dir(&src_dir)
                .stdout_capture()
                .run()
                .unwrap();
        }
        freebsd => {
            src_dir = clone(download_dir, "freebsd/freebsd-src", None, &["/include/", "/sys/"]);
            // TODO: use https://github.com/freebsd/freebsd-src/blob/HEAD/Makefile?
            for path in ["sys"] {
                symlink(src_dir.join("sys").join(path), src_dir.join("include").join(path))
                    .unwrap();
            }
            // https://github.com/freebsd/freebsd-src/tree/HEAD/sys
            let arches = match target.arch {
                x86_64 => &["amd64", "x86"][..],
                arm => &["arm"],
                aarch64 => &["arm64"],
                x86 => &["i386", "x86"],
                powerpc | powerpc64 => &["powerpc"],
                riscv64 => &["riscv"],
                _ => todo!("{target:?}"),
            };
            symlink(
                src_dir.join("sys").join(arches[0]).join("include"),
                src_dir.join("include/machine"),
            )
            .unwrap();
            for &arch in &arches[1..] {
                symlink(
                    src_dir.join("sys").join(arch).join("include"),
                    src_dir.join("include").join(arch),
                )
                .unwrap();
            }
        }
        netbsd => {
            src_dir = clone(download_dir, "NetBSD/src", None, &[]);
            for path in ["sys", "uvm"] {
                symlink(src_dir.join("sys").join(path), src_dir.join("include").join(path))
                    .unwrap();
            }
            // https://wiki.netbsd.org/ports
            // https://github.com/NetBSD/src/tree/HEAD/sys/arch
            let arches = match target.arch {
                aarch64 => &["aarch64", "arm"][..],
                x86_64 => &["amd64", "x86"],
                arm => &["arm"],
                x86 => &["i386", "x86"],
                m68k => &["m68k"],
                mips | mips32r6 | mips64 | mips64r6 => &["mips"],
                powerpc | powerpc64 => &["powerpc"],
                riscv32 | riscv64 => &["riscv"],
                sparc => &["sparc"],
                sparc64 => &["sparc64", "sparc"],
                _ => todo!("{target:?}"),
            };
            for &arch in arches {
                symlink(
                    src_dir.join("sys/arch").join(arch).join("include"),
                    src_dir.join("include").join(arch),
                )
                .unwrap();
            }
            symlink(src_dir.join("include").join(arches[0]), src_dir.join("include/machine"))
                .unwrap();
            match target.arch {
                mips | mips32r6 | mips64 | mips64r6 => {
                    // TODO
                    fs::copy(
                        src_dir.join("sys/arch/evbmips/include/param.h"),
                        src_dir.join("sys/arch/mips/include/param.h"),
                    )
                    .unwrap();
                }
                _ => {}
            }
        }
        openbsd => {
            src_dir = clone(download_dir, "openbsd/src", None, &["/include/", "/sys/"]);
            // TODO: use https://github.com/openbsd/src/blob/HEAD/Makefile?
            for path in ["sys", "uvm"] {
                symlink(src_dir.join("sys").join(path), src_dir.join("include").join(path))
                    .unwrap();
            }
            // https://www.openbsd.org/plat.html
            // https://github.com/openbsd/src/tree/HEAD/sys/arch
            let arches = match target.arch {
                x86_64 => &["amd64"][..],
                aarch64 => &["arm64"],
                arm => &["armv7", "arm"],
                x86 => &["i386"],
                mips64 | mips64r6 => match target.target_endian {
                    big => &["octeon", "mips64"],
                    little => &["loongson", "mips64"],
                },
                powerpc => &["macppc", "powerpc"],
                powerpc64 => &["powerpc64"],
                riscv64 => &["riscv64"],
                sparc64 => &["sparc64"],
                _ => todo!("{target:?}"),
            };
            for &arch in arches {
                symlink(
                    src_dir.join("sys/arch").join(arch).join("include"),
                    src_dir.join("include").join(arch),
                )
                .unwrap();
            }
            symlink(src_dir.join("include").join(arches[0]), src_dir.join("include/machine"))
                .unwrap();
        }
        solaris => {
            let arch = solaris_arch(target);
            let name = &format!("headers/solaris/{arch}");
            let headers_dir = download_dir.join(name);
            src_dir = headers_dir.clone();
            if headers_dir.exists() {
                patched = true;
            } else {
                // For now, refers dilos2's system-header package as with std: https://github.com/rust-lang/rust/blob/1.85.0/src/ci/docker/host-x86_64/dist-various-2/Dockerfile#L31
                let system_header = match target.arch {
                    // https://apt.dilos.org/dilos/dists/dilos2/main/binary-solaris-sparc/Packages
                    sparc64 => "pool/main/s/system-header/system-header_2.0.3.11_solaris-sparc.deb",
                    // https://apt.dilos.org/dilos/dists/dilos2/main/binary-solaris-i386/Packages
                    x86_64 => "pool/main/d/dg2/system-header_2.0.3.36_solaris-i386.deb",
                    _ => todo!("{target:?}"),
                };
                curl(
                    download_dir,
                    name,
                    &format!("https://apt.dilos.org/dilos/{system_header}"),
                    "",
                    "0",
                );
            }
        }
        illumos => {
            let mut repository = "illumos/illumos-gate";
            if target.arch == aarch64 {
                // TODO: use illumos/illumos-gate once merged to upstream
                repository = "richlowe/illumos-gate";
            }
            src_dir = clone(download_dir, repository, None, &["/usr/"]);
        }
        fuchsia => {
            src_dir = clone(download_dir, "https://fuchsia.googlesource.com/fuchsia", None, &[]);
            fs::write(src_dir.join("zircon/kernel/lib/libc/include/stdbool.h"), "").unwrap();
            fs::write(
                src_dir.join("zircon/kernel/lib/libc/include/stddef.h"),
                "#define size_t unsigned long",
            )
            .unwrap();
        }
        _ => todo!("{target:?}"),
    }
    if !patched {
        patch(target, &src_dir);
    }
    src_dir
}

fn linux_gcc(target: &TargetSpec) -> (String, String) {
    assert_eq!(target.os, linux);
    let mut llvm_target = target.llvm_target.clone();
    if target.env != gnu {
        llvm_target = llvm_target.replace(target.env.as_str(), "gnu");
    }
    let mut cflags = String::new();
    let mut cc = format!("{}-gcc", llvm_target.replace("-unknown", ""));
    let mut cc_found = cmd!(&cc, "--version").stdout_capture().stderr_capture().run().is_ok();
    for suffix in ["-14", "-13"] {
        if !cc_found {
            cc += suffix;
            cc_found = cmd!(&cc, "--version").stdout_capture().stderr_capture().run().is_ok();
            if cc_found {
                break;
            }
            for _ in 0..suffix.len() {
                cc.pop();
            }
        }
    }
    if !cc_found {
        cc = format!("{llvm_target}-gcc");
        cc_found = cmd!(&cc, "--version").stdout_capture().stderr_capture().run().is_ok();
    }
    if !cc_found {
        // select alternative cc
        match target.arch {
            aarch64 => {
                cc = "aarch64-linux-gnu-gcc".to_owned();
                if target.target_pointer_width == "32" {
                    cflags += " -mabi=ilp32";
                }
                if target.target_endian == big {
                    cflags += " -mbig-endian";
                }
            }
            arm if !llvm_target.ends_with("hf") => {
                cc = "arm-linux-gnueabi-gcc".to_owned();
                if target.target_endian == big {
                    cflags += " -mbig-endian";
                }
            }
            mips | mips32r6 | mips64 | mips64r6 => {
                cc = "mips64el-linux-gnuabi64-gcc".to_owned();
                if matches!(target.arch, mips | mips32r6) {
                    cflags += " -mabi=32";
                } else if target.target_pointer_width == "32" {
                    cflags += " -mabi=n32";
                }
                match target.arch {
                    mips => cflags += " -mips32r2",
                    mips32r6 => cflags += " -mips32r6",
                    mips64 => cflags += " -mips64r2",
                    mips64r6 => cflags += " -mips64r6",
                    _ => unreachable!(),
                }
                if target.target_endian == big {
                    cflags += " -meb";
                }
            }
            powerpc | powerpc64 if target.target_endian == big => {
                cc = "powerpc64le-linux-gnu-gcc".to_owned();
                if target.arch == powerpc {
                    cflags += " -m32";
                }
                cflags += " -mbig-endian";
            }
            riscv32 => {
                cc = "riscv64-linux-gnu-gcc".to_owned();
                cflags += " -march=rv32gc -mabi=ilp32d";
            }
            sparc => {
                cc = "sparc64-linux-gnu-gcc".to_owned();
                cflags += " -m32 -mv8plus";
            }
            x86 | x86_64 => {
                cc = "x86_64-linux-gnu-gcc".to_owned();
                if target.arch == x86 {
                    cflags += " -m32";
                    if llvm_target.starts_with("i586") {
                        cflags += " -march=pentium";
                    }
                } else if target.target_pointer_width == "32" {
                    cflags += " -mx32";
                }
            }
            _ => panic!(
                "{}-gcc or {}-gcc required",
                llvm_target.replace("-unknown", ""),
                llvm_target
            ),
        }
    }
    (cc, cflags)
}

fn linux_headers_dir(target: &TargetSpec, src_dir: &Utf8Path) -> Utf8PathBuf {
    if target.arch == aarch64 && target.target_pointer_width == "32" {
        src_dir.join("../..").join("headers").join("linux").join("arm64-ilp32")
    } else {
        src_dir.join("../..").join("headers").join("linux").join(linux_arch(target))
    }
}
fn glibc_dir(target: &TargetSpec, src_dir: &Utf8Path) -> Utf8PathBuf {
    if target.arch == aarch64 && target.target_pointer_width == "32" {
        src_dir.join("../..").join("linaro-toolchain/glibc")
    } else {
        src_dir.join("../..").join(GLIBC_REPO)
    }
}
fn libc_headers_dir(target: &TargetSpec, src_dir: &Utf8Path) -> Utf8PathBuf {
    assert_eq!(target.os, linux);
    let dir = src_dir.join("../..").join("headers");
    match target.env {
        gnu => dir.join("glibc").join(target.llvm_target.replace("-unknown", "")),
        musl => dir.join("musl").join(target.llvm_target.replace("-unknown", "")),
        uclibc => dir.join("uclibc").join(target.llvm_target.replace("-unknown", "")),
        _ => todo!("{target:?}"),
    }
}
fn bionic_dir(src_dir: &Utf8Path) -> Utf8PathBuf {
    src_dir.join("../..").join(BIONIC_REPO)
}

fn linux_arch(target: &TargetSpec) -> &'static str {
    // https://github.com/torvalds/linux/tree/HEAD/arch
    match target.arch {
        arm => "arm",
        aarch64 => "arm64",
        csky => "csky",
        hexagon => "hexagon",
        loongarch64 => "loongarch",
        m68k => "m68k",
        mips | mips32r6 | mips64 | mips64r6 => "mips",
        powerpc | powerpc64 => "powerpc",
        riscv32 | riscv64 => "riscv",
        s390x => "s390",
        sparc | sparc64 => "sparc",
        x86 | x86_64 => "x86",
        xtensa => "xtensa",
        _ => todo!("{target:?}"),
    }
}
fn musl_arch(target: &TargetSpec) -> &'static str {
    // https://github.com/bminor/musl/tree/HEAD/arch
    // https://github.com/quic/musl/tree/bcain/to-upstream
    match target.arch {
        aarch64 => "aarch64",
        arm => "arm",
        hexagon => "hexagon",
        x86 => "i386",
        loongarch64 => "loongarch64",
        m68k => "m68k",
        mips | mips32r6 => "mips",
        mips64 | mips64r6 if target.target_pointer_width == "64" => "mips64",
        mips64 | mips64r6 if target.target_pointer_width == "32" => "mipsn32",
        powerpc => "powerpc",
        powerpc64 => "powerpc64",
        riscv32 => "riscv32",
        riscv64 => "riscv64",
        s390x => "s390x",
        x86_64 if target.target_pointer_width == "32" => "x32",
        x86_64 if target.target_pointer_width == "64" => "x86_64",
        _ => todo!("{target:?}"),
    }
}
fn uclibc_arch(target: &TargetSpec) -> &'static str {
    // https://github.com/wbx-github/uclibc-ng/tree/HEAD/libc/sysdeps/linux
    match target.arch {
        aarch64 => "aarch64",
        arm => "arm",
        csky => "csky",
        x86 => "i386",
        m68k => "m68k",
        mips | mips32r6 => "mips",
        powerpc => "powerpc",
        riscv32 => "riscv32",
        riscv64 => "riscv64",
        sparc => "sparc",
        sparc64 => "sparc64",
        x86_64 => "x86_64",
        xtensa => "xtensa",
        _ => todo!("{target:?}"),
    }
}
fn l4re_arch(target: &TargetSpec) -> &'static str {
    // https://os.inf.tu-dresden.de/download/snapshots/toolchain/
    // https://github.com/kernkonzept/l4re-core/tree/HEAD/l4sys/include
    match target.arch {
        aarch64 => "arm64",
        x86_64 => "x86_64",
        _ => todo!("{target:?}"),
    }
}
fn solaris_arch(target: &TargetSpec) -> &'static str {
    match target.arch {
        sparc64 => "sparc",
        x86_64 => "i386",
        _ => todo!("{target:?}"),
    }
}
fn illumos_arch(target: &TargetSpec) -> &'static str {
    // https://github.com/illumos/illumos-gate/tree/HEAD/usr/src/uts
    // https://github.com/richlowe/illumos-gate/tree/arm64-gate/usr/src/uts
    match target.arch {
        aarch64 => "aarch64",
        _ => todo!("{target:?}"),
    }
}

#[track_caller]
fn target_spec_json(target: &str) -> TargetSpec {
    let spec_path = workspace_root().join("target-specs").join(target).with_extension("json");
    let target = if spec_path.exists() { spec_path.as_str() } else { target };
    target_spec_json::target_spec_json(Command::new("rustc"), target).unwrap()
}

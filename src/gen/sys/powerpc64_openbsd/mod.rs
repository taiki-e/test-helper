// SPDX-License-Identifier: Apache-2.0 OR MIT
// This file is @generated by test-helper-internal-codegen
// (gen function at tools/codegen/src/ffi.rs).
// It is not intended for manual editing.

#![cfg_attr(rustfmt, rustfmt::skip)]
mod dlfcn;
pub use dlfcn::RTLD_DEFAULT;
pub use dlfcn::dlsym;
mod sys_auxv;
pub use sys_auxv::AT_NULL;
pub use sys_auxv::AT_IGNORE;
pub use sys_auxv::AT_PAGESZ;
pub use sys_auxv::AT_HWCAP;
pub use sys_auxv::AT_HWCAP2;
pub use sys_auxv::AT_COUNT;
pub use sys_auxv::elf_aux_info;
mod sys_sysctl;
pub use sys_sysctl::CTL_MACHDEP;
pub use sys_sysctl::sysctl;
mod machine_cpu;
pub use machine_cpu::CPU_ALTIVEC;
pub use machine_cpu::CPU_MAXID;
mod machine_elf;
pub use machine_elf::PPC_FEATURE_32;
pub use machine_elf::PPC_FEATURE_64;
pub use machine_elf::PPC_FEATURE_601_INSTR;
pub use machine_elf::PPC_FEATURE_HAS_ALTIVEC;
pub use machine_elf::PPC_FEATURE_HAS_FPU;
pub use machine_elf::PPC_FEATURE_HAS_MMU;
pub use machine_elf::PPC_FEATURE_UNIFIED_CACHE;
pub use machine_elf::PPC_FEATURE_HAS_SPE;
pub use machine_elf::PPC_FEATURE_HAS_EFP_SINGLE;
pub use machine_elf::PPC_FEATURE_HAS_EFP_DOUBLE;
pub use machine_elf::PPC_FEATURE_NO_TB;
pub use machine_elf::PPC_FEATURE_POWER4;
pub use machine_elf::PPC_FEATURE_POWER5;
pub use machine_elf::PPC_FEATURE_POWER5_PLUS;
pub use machine_elf::PPC_FEATURE_CELL;
pub use machine_elf::PPC_FEATURE_BOOKE;
pub use machine_elf::PPC_FEATURE_SMT;
pub use machine_elf::PPC_FEATURE_ICACHE_SNOOP;
pub use machine_elf::PPC_FEATURE_ARCH_2_05;
pub use machine_elf::PPC_FEATURE_HAS_DFP;
pub use machine_elf::PPC_FEATURE_POWER6_EXT;
pub use machine_elf::PPC_FEATURE_ARCH_2_06;
pub use machine_elf::PPC_FEATURE_HAS_VSX;
pub use machine_elf::PPC_FEATURE_TRUE_LE;
pub use machine_elf::PPC_FEATURE_PPC_LE;
pub use machine_elf::PPC_FEATURE2_ARCH_2_07;
pub use machine_elf::PPC_FEATURE2_HTM;
pub use machine_elf::PPC_FEATURE2_DSCR;
pub use machine_elf::PPC_FEATURE2_EBB;
pub use machine_elf::PPC_FEATURE2_ISEL;
pub use machine_elf::PPC_FEATURE2_TAR;
pub use machine_elf::PPC_FEATURE2_HAS_VEC_CRYPTO;
pub use machine_elf::PPC_FEATURE2_HTM_NOSC;
pub use machine_elf::PPC_FEATURE2_ARCH_3_00;
pub use machine_elf::PPC_FEATURE2_HAS_IEEE128;
pub use machine_elf::PPC_FEATURE2_DARN;
pub use machine_elf::PPC_FEATURE2_SCV;
pub use machine_elf::PPC_FEATURE2_HTM_NOSUSPEND;
pub type c_char = u8;

// SPDX-License-Identifier: Apache-2.0 OR MIT
// This file is @generated by test-helper-internal-codegen
// (generate function at tools/codegen/src/ffi.rs).
// It is not intended for manual editing.

#![cfg_attr(rustfmt, rustfmt::skip)]
mod linux_headers_asm_hwcap;
pub use self::linux_headers_asm_hwcap::HWCAP_SWP;
pub use self::linux_headers_asm_hwcap::HWCAP_HALF;
pub use self::linux_headers_asm_hwcap::HWCAP_THUMB;
pub use self::linux_headers_asm_hwcap::HWCAP_26BIT;
pub use self::linux_headers_asm_hwcap::HWCAP_FAST_MULT;
pub use self::linux_headers_asm_hwcap::HWCAP_FPA;
pub use self::linux_headers_asm_hwcap::HWCAP_VFP;
pub use self::linux_headers_asm_hwcap::HWCAP_EDSP;
pub use self::linux_headers_asm_hwcap::HWCAP_JAVA;
pub use self::linux_headers_asm_hwcap::HWCAP_IWMMXT;
pub use self::linux_headers_asm_hwcap::HWCAP_CRUNCH;
pub use self::linux_headers_asm_hwcap::HWCAP_THUMBEE;
pub use self::linux_headers_asm_hwcap::HWCAP_NEON;
pub use self::linux_headers_asm_hwcap::HWCAP_VFPv3;
pub use self::linux_headers_asm_hwcap::HWCAP_VFPv3D16;
pub use self::linux_headers_asm_hwcap::HWCAP_TLS;
pub use self::linux_headers_asm_hwcap::HWCAP_VFPv4;
pub use self::linux_headers_asm_hwcap::HWCAP_IDIVA;
pub use self::linux_headers_asm_hwcap::HWCAP_IDIVT;
pub use self::linux_headers_asm_hwcap::HWCAP_VFPD32;
pub use self::linux_headers_asm_hwcap::HWCAP_IDIV;
pub use self::linux_headers_asm_hwcap::HWCAP_LPAE;
pub use self::linux_headers_asm_hwcap::HWCAP_EVTSTRM;
pub use self::linux_headers_asm_hwcap::HWCAP_FPHP;
pub use self::linux_headers_asm_hwcap::HWCAP_ASIMDHP;
pub use self::linux_headers_asm_hwcap::HWCAP_ASIMDDP;
pub use self::linux_headers_asm_hwcap::HWCAP_ASIMDFHM;
pub use self::linux_headers_asm_hwcap::HWCAP_ASIMDBF16;
pub use self::linux_headers_asm_hwcap::HWCAP_I8MM;
pub use self::linux_headers_asm_hwcap::HWCAP2_AES;
pub use self::linux_headers_asm_hwcap::HWCAP2_PMULL;
pub use self::linux_headers_asm_hwcap::HWCAP2_SHA1;
pub use self::linux_headers_asm_hwcap::HWCAP2_SHA2;
pub use self::linux_headers_asm_hwcap::HWCAP2_CRC32;
pub use self::linux_headers_asm_hwcap::HWCAP2_SB;
pub use self::linux_headers_asm_hwcap::HWCAP2_SSBS;
mod linux_headers_asm_unistd;
pub use self::linux_headers_asm_unistd::__NR_OABI_SYSCALL_BASE;
pub use self::linux_headers_asm_unistd::__NR_SYSCALL_MASK;
pub use self::linux_headers_asm_unistd::__NR_SYSCALL_BASE;
pub use self::linux_headers_asm_unistd::__NR_restart_syscall;
pub use self::linux_headers_asm_unistd::__NR_exit;
pub use self::linux_headers_asm_unistd::__NR_fork;
pub use self::linux_headers_asm_unistd::__NR_read;
pub use self::linux_headers_asm_unistd::__NR_write;
pub use self::linux_headers_asm_unistd::__NR_open;
pub use self::linux_headers_asm_unistd::__NR_close;
pub use self::linux_headers_asm_unistd::__NR_creat;
pub use self::linux_headers_asm_unistd::__NR_link;
pub use self::linux_headers_asm_unistd::__NR_unlink;
pub use self::linux_headers_asm_unistd::__NR_execve;
pub use self::linux_headers_asm_unistd::__NR_chdir;
pub use self::linux_headers_asm_unistd::__NR_mknod;
pub use self::linux_headers_asm_unistd::__NR_chmod;
pub use self::linux_headers_asm_unistd::__NR_lchown;
pub use self::linux_headers_asm_unistd::__NR_lseek;
pub use self::linux_headers_asm_unistd::__NR_getpid;
pub use self::linux_headers_asm_unistd::__NR_mount;
pub use self::linux_headers_asm_unistd::__NR_setuid;
pub use self::linux_headers_asm_unistd::__NR_getuid;
pub use self::linux_headers_asm_unistd::__NR_ptrace;
pub use self::linux_headers_asm_unistd::__NR_pause;
pub use self::linux_headers_asm_unistd::__NR_access;
pub use self::linux_headers_asm_unistd::__NR_nice;
pub use self::linux_headers_asm_unistd::__NR_sync;
pub use self::linux_headers_asm_unistd::__NR_kill;
pub use self::linux_headers_asm_unistd::__NR_rename;
pub use self::linux_headers_asm_unistd::__NR_mkdir;
pub use self::linux_headers_asm_unistd::__NR_rmdir;
pub use self::linux_headers_asm_unistd::__NR_dup;
pub use self::linux_headers_asm_unistd::__NR_pipe;
pub use self::linux_headers_asm_unistd::__NR_times;
pub use self::linux_headers_asm_unistd::__NR_brk;
pub use self::linux_headers_asm_unistd::__NR_setgid;
pub use self::linux_headers_asm_unistd::__NR_getgid;
pub use self::linux_headers_asm_unistd::__NR_geteuid;
pub use self::linux_headers_asm_unistd::__NR_getegid;
pub use self::linux_headers_asm_unistd::__NR_acct;
pub use self::linux_headers_asm_unistd::__NR_umount2;
pub use self::linux_headers_asm_unistd::__NR_ioctl;
pub use self::linux_headers_asm_unistd::__NR_fcntl;
pub use self::linux_headers_asm_unistd::__NR_setpgid;
pub use self::linux_headers_asm_unistd::__NR_umask;
pub use self::linux_headers_asm_unistd::__NR_chroot;
pub use self::linux_headers_asm_unistd::__NR_ustat;
pub use self::linux_headers_asm_unistd::__NR_dup2;
pub use self::linux_headers_asm_unistd::__NR_getppid;
pub use self::linux_headers_asm_unistd::__NR_getpgrp;
pub use self::linux_headers_asm_unistd::__NR_setsid;
pub use self::linux_headers_asm_unistd::__NR_sigaction;
pub use self::linux_headers_asm_unistd::__NR_setreuid;
pub use self::linux_headers_asm_unistd::__NR_setregid;
pub use self::linux_headers_asm_unistd::__NR_sigsuspend;
pub use self::linux_headers_asm_unistd::__NR_sigpending;
pub use self::linux_headers_asm_unistd::__NR_sethostname;
pub use self::linux_headers_asm_unistd::__NR_setrlimit;
pub use self::linux_headers_asm_unistd::__NR_getrusage;
pub use self::linux_headers_asm_unistd::__NR_gettimeofday;
pub use self::linux_headers_asm_unistd::__NR_settimeofday;
pub use self::linux_headers_asm_unistd::__NR_getgroups;
pub use self::linux_headers_asm_unistd::__NR_setgroups;
pub use self::linux_headers_asm_unistd::__NR_symlink;
pub use self::linux_headers_asm_unistd::__NR_readlink;
pub use self::linux_headers_asm_unistd::__NR_uselib;
pub use self::linux_headers_asm_unistd::__NR_swapon;
pub use self::linux_headers_asm_unistd::__NR_reboot;
pub use self::linux_headers_asm_unistd::__NR_munmap;
pub use self::linux_headers_asm_unistd::__NR_truncate;
pub use self::linux_headers_asm_unistd::__NR_ftruncate;
pub use self::linux_headers_asm_unistd::__NR_fchmod;
pub use self::linux_headers_asm_unistd::__NR_fchown;
pub use self::linux_headers_asm_unistd::__NR_getpriority;
pub use self::linux_headers_asm_unistd::__NR_setpriority;
pub use self::linux_headers_asm_unistd::__NR_statfs;
pub use self::linux_headers_asm_unistd::__NR_fstatfs;
pub use self::linux_headers_asm_unistd::__NR_syslog;
pub use self::linux_headers_asm_unistd::__NR_setitimer;
pub use self::linux_headers_asm_unistd::__NR_getitimer;
pub use self::linux_headers_asm_unistd::__NR_stat;
pub use self::linux_headers_asm_unistd::__NR_lstat;
pub use self::linux_headers_asm_unistd::__NR_fstat;
pub use self::linux_headers_asm_unistd::__NR_vhangup;
pub use self::linux_headers_asm_unistd::__NR_wait4;
pub use self::linux_headers_asm_unistd::__NR_swapoff;
pub use self::linux_headers_asm_unistd::__NR_sysinfo;
pub use self::linux_headers_asm_unistd::__NR_fsync;
pub use self::linux_headers_asm_unistd::__NR_sigreturn;
pub use self::linux_headers_asm_unistd::__NR_clone;
pub use self::linux_headers_asm_unistd::__NR_setdomainname;
pub use self::linux_headers_asm_unistd::__NR_uname;
pub use self::linux_headers_asm_unistd::__NR_adjtimex;
pub use self::linux_headers_asm_unistd::__NR_mprotect;
pub use self::linux_headers_asm_unistd::__NR_sigprocmask;
pub use self::linux_headers_asm_unistd::__NR_init_module;
pub use self::linux_headers_asm_unistd::__NR_delete_module;
pub use self::linux_headers_asm_unistd::__NR_quotactl;
pub use self::linux_headers_asm_unistd::__NR_getpgid;
pub use self::linux_headers_asm_unistd::__NR_fchdir;
pub use self::linux_headers_asm_unistd::__NR_bdflush;
pub use self::linux_headers_asm_unistd::__NR_sysfs;
pub use self::linux_headers_asm_unistd::__NR_personality;
pub use self::linux_headers_asm_unistd::__NR_setfsuid;
pub use self::linux_headers_asm_unistd::__NR_setfsgid;
pub use self::linux_headers_asm_unistd::__NR__llseek;
pub use self::linux_headers_asm_unistd::__NR_getdents;
pub use self::linux_headers_asm_unistd::__NR__newselect;
pub use self::linux_headers_asm_unistd::__NR_flock;
pub use self::linux_headers_asm_unistd::__NR_msync;
pub use self::linux_headers_asm_unistd::__NR_readv;
pub use self::linux_headers_asm_unistd::__NR_writev;
pub use self::linux_headers_asm_unistd::__NR_getsid;
pub use self::linux_headers_asm_unistd::__NR_fdatasync;
pub use self::linux_headers_asm_unistd::__NR__sysctl;
pub use self::linux_headers_asm_unistd::__NR_mlock;
pub use self::linux_headers_asm_unistd::__NR_munlock;
pub use self::linux_headers_asm_unistd::__NR_mlockall;
pub use self::linux_headers_asm_unistd::__NR_munlockall;
pub use self::linux_headers_asm_unistd::__NR_sched_setparam;
pub use self::linux_headers_asm_unistd::__NR_sched_getparam;
pub use self::linux_headers_asm_unistd::__NR_sched_setscheduler;
pub use self::linux_headers_asm_unistd::__NR_sched_getscheduler;
pub use self::linux_headers_asm_unistd::__NR_sched_yield;
pub use self::linux_headers_asm_unistd::__NR_sched_get_priority_max;
pub use self::linux_headers_asm_unistd::__NR_sched_get_priority_min;
pub use self::linux_headers_asm_unistd::__NR_sched_rr_get_interval;
pub use self::linux_headers_asm_unistd::__NR_nanosleep;
pub use self::linux_headers_asm_unistd::__NR_mremap;
pub use self::linux_headers_asm_unistd::__NR_setresuid;
pub use self::linux_headers_asm_unistd::__NR_getresuid;
pub use self::linux_headers_asm_unistd::__NR_poll;
pub use self::linux_headers_asm_unistd::__NR_nfsservctl;
pub use self::linux_headers_asm_unistd::__NR_setresgid;
pub use self::linux_headers_asm_unistd::__NR_getresgid;
pub use self::linux_headers_asm_unistd::__NR_prctl;
pub use self::linux_headers_asm_unistd::__NR_rt_sigreturn;
pub use self::linux_headers_asm_unistd::__NR_rt_sigaction;
pub use self::linux_headers_asm_unistd::__NR_rt_sigprocmask;
pub use self::linux_headers_asm_unistd::__NR_rt_sigpending;
pub use self::linux_headers_asm_unistd::__NR_rt_sigtimedwait;
pub use self::linux_headers_asm_unistd::__NR_rt_sigqueueinfo;
pub use self::linux_headers_asm_unistd::__NR_rt_sigsuspend;
pub use self::linux_headers_asm_unistd::__NR_pread64;
pub use self::linux_headers_asm_unistd::__NR_pwrite64;
pub use self::linux_headers_asm_unistd::__NR_chown;
pub use self::linux_headers_asm_unistd::__NR_getcwd;
pub use self::linux_headers_asm_unistd::__NR_capget;
pub use self::linux_headers_asm_unistd::__NR_capset;
pub use self::linux_headers_asm_unistd::__NR_sigaltstack;
pub use self::linux_headers_asm_unistd::__NR_sendfile;
pub use self::linux_headers_asm_unistd::__NR_vfork;
pub use self::linux_headers_asm_unistd::__NR_ugetrlimit;
pub use self::linux_headers_asm_unistd::__NR_mmap2;
pub use self::linux_headers_asm_unistd::__NR_truncate64;
pub use self::linux_headers_asm_unistd::__NR_ftruncate64;
pub use self::linux_headers_asm_unistd::__NR_stat64;
pub use self::linux_headers_asm_unistd::__NR_lstat64;
pub use self::linux_headers_asm_unistd::__NR_fstat64;
pub use self::linux_headers_asm_unistd::__NR_lchown32;
pub use self::linux_headers_asm_unistd::__NR_getuid32;
pub use self::linux_headers_asm_unistd::__NR_getgid32;
pub use self::linux_headers_asm_unistd::__NR_geteuid32;
pub use self::linux_headers_asm_unistd::__NR_getegid32;
pub use self::linux_headers_asm_unistd::__NR_setreuid32;
pub use self::linux_headers_asm_unistd::__NR_setregid32;
pub use self::linux_headers_asm_unistd::__NR_getgroups32;
pub use self::linux_headers_asm_unistd::__NR_setgroups32;
pub use self::linux_headers_asm_unistd::__NR_fchown32;
pub use self::linux_headers_asm_unistd::__NR_setresuid32;
pub use self::linux_headers_asm_unistd::__NR_getresuid32;
pub use self::linux_headers_asm_unistd::__NR_setresgid32;
pub use self::linux_headers_asm_unistd::__NR_getresgid32;
pub use self::linux_headers_asm_unistd::__NR_chown32;
pub use self::linux_headers_asm_unistd::__NR_setuid32;
pub use self::linux_headers_asm_unistd::__NR_setgid32;
pub use self::linux_headers_asm_unistd::__NR_setfsuid32;
pub use self::linux_headers_asm_unistd::__NR_setfsgid32;
pub use self::linux_headers_asm_unistd::__NR_getdents64;
pub use self::linux_headers_asm_unistd::__NR_pivot_root;
pub use self::linux_headers_asm_unistd::__NR_mincore;
pub use self::linux_headers_asm_unistd::__NR_madvise;
pub use self::linux_headers_asm_unistd::__NR_fcntl64;
pub use self::linux_headers_asm_unistd::__NR_gettid;
pub use self::linux_headers_asm_unistd::__NR_readahead;
pub use self::linux_headers_asm_unistd::__NR_setxattr;
pub use self::linux_headers_asm_unistd::__NR_lsetxattr;
pub use self::linux_headers_asm_unistd::__NR_fsetxattr;
pub use self::linux_headers_asm_unistd::__NR_getxattr;
pub use self::linux_headers_asm_unistd::__NR_lgetxattr;
pub use self::linux_headers_asm_unistd::__NR_fgetxattr;
pub use self::linux_headers_asm_unistd::__NR_listxattr;
pub use self::linux_headers_asm_unistd::__NR_llistxattr;
pub use self::linux_headers_asm_unistd::__NR_flistxattr;
pub use self::linux_headers_asm_unistd::__NR_removexattr;
pub use self::linux_headers_asm_unistd::__NR_lremovexattr;
pub use self::linux_headers_asm_unistd::__NR_fremovexattr;
pub use self::linux_headers_asm_unistd::__NR_tkill;
pub use self::linux_headers_asm_unistd::__NR_sendfile64;
pub use self::linux_headers_asm_unistd::__NR_futex;
pub use self::linux_headers_asm_unistd::__NR_sched_setaffinity;
pub use self::linux_headers_asm_unistd::__NR_sched_getaffinity;
pub use self::linux_headers_asm_unistd::__NR_io_setup;
pub use self::linux_headers_asm_unistd::__NR_io_destroy;
pub use self::linux_headers_asm_unistd::__NR_io_getevents;
pub use self::linux_headers_asm_unistd::__NR_io_submit;
pub use self::linux_headers_asm_unistd::__NR_io_cancel;
pub use self::linux_headers_asm_unistd::__NR_exit_group;
pub use self::linux_headers_asm_unistd::__NR_lookup_dcookie;
pub use self::linux_headers_asm_unistd::__NR_epoll_create;
pub use self::linux_headers_asm_unistd::__NR_epoll_ctl;
pub use self::linux_headers_asm_unistd::__NR_epoll_wait;
pub use self::linux_headers_asm_unistd::__NR_remap_file_pages;
pub use self::linux_headers_asm_unistd::__NR_set_tid_address;
pub use self::linux_headers_asm_unistd::__NR_timer_create;
pub use self::linux_headers_asm_unistd::__NR_timer_settime;
pub use self::linux_headers_asm_unistd::__NR_timer_gettime;
pub use self::linux_headers_asm_unistd::__NR_timer_getoverrun;
pub use self::linux_headers_asm_unistd::__NR_timer_delete;
pub use self::linux_headers_asm_unistd::__NR_clock_settime;
pub use self::linux_headers_asm_unistd::__NR_clock_gettime;
pub use self::linux_headers_asm_unistd::__NR_clock_getres;
pub use self::linux_headers_asm_unistd::__NR_clock_nanosleep;
pub use self::linux_headers_asm_unistd::__NR_statfs64;
pub use self::linux_headers_asm_unistd::__NR_fstatfs64;
pub use self::linux_headers_asm_unistd::__NR_tgkill;
pub use self::linux_headers_asm_unistd::__NR_utimes;
pub use self::linux_headers_asm_unistd::__NR_arm_fadvise64_64;
pub use self::linux_headers_asm_unistd::__NR_pciconfig_iobase;
pub use self::linux_headers_asm_unistd::__NR_pciconfig_read;
pub use self::linux_headers_asm_unistd::__NR_pciconfig_write;
pub use self::linux_headers_asm_unistd::__NR_mq_open;
pub use self::linux_headers_asm_unistd::__NR_mq_unlink;
pub use self::linux_headers_asm_unistd::__NR_mq_timedsend;
pub use self::linux_headers_asm_unistd::__NR_mq_timedreceive;
pub use self::linux_headers_asm_unistd::__NR_mq_notify;
pub use self::linux_headers_asm_unistd::__NR_mq_getsetattr;
pub use self::linux_headers_asm_unistd::__NR_waitid;
pub use self::linux_headers_asm_unistd::__NR_socket;
pub use self::linux_headers_asm_unistd::__NR_bind;
pub use self::linux_headers_asm_unistd::__NR_connect;
pub use self::linux_headers_asm_unistd::__NR_listen;
pub use self::linux_headers_asm_unistd::__NR_accept;
pub use self::linux_headers_asm_unistd::__NR_getsockname;
pub use self::linux_headers_asm_unistd::__NR_getpeername;
pub use self::linux_headers_asm_unistd::__NR_socketpair;
pub use self::linux_headers_asm_unistd::__NR_send;
pub use self::linux_headers_asm_unistd::__NR_sendto;
pub use self::linux_headers_asm_unistd::__NR_recv;
pub use self::linux_headers_asm_unistd::__NR_recvfrom;
pub use self::linux_headers_asm_unistd::__NR_shutdown;
pub use self::linux_headers_asm_unistd::__NR_setsockopt;
pub use self::linux_headers_asm_unistd::__NR_getsockopt;
pub use self::linux_headers_asm_unistd::__NR_sendmsg;
pub use self::linux_headers_asm_unistd::__NR_recvmsg;
pub use self::linux_headers_asm_unistd::__NR_semop;
pub use self::linux_headers_asm_unistd::__NR_semget;
pub use self::linux_headers_asm_unistd::__NR_semctl;
pub use self::linux_headers_asm_unistd::__NR_msgsnd;
pub use self::linux_headers_asm_unistd::__NR_msgrcv;
pub use self::linux_headers_asm_unistd::__NR_msgget;
pub use self::linux_headers_asm_unistd::__NR_msgctl;
pub use self::linux_headers_asm_unistd::__NR_shmat;
pub use self::linux_headers_asm_unistd::__NR_shmdt;
pub use self::linux_headers_asm_unistd::__NR_shmget;
pub use self::linux_headers_asm_unistd::__NR_shmctl;
pub use self::linux_headers_asm_unistd::__NR_add_key;
pub use self::linux_headers_asm_unistd::__NR_request_key;
pub use self::linux_headers_asm_unistd::__NR_keyctl;
pub use self::linux_headers_asm_unistd::__NR_semtimedop;
pub use self::linux_headers_asm_unistd::__NR_vserver;
pub use self::linux_headers_asm_unistd::__NR_ioprio_set;
pub use self::linux_headers_asm_unistd::__NR_ioprio_get;
pub use self::linux_headers_asm_unistd::__NR_inotify_init;
pub use self::linux_headers_asm_unistd::__NR_inotify_add_watch;
pub use self::linux_headers_asm_unistd::__NR_inotify_rm_watch;
pub use self::linux_headers_asm_unistd::__NR_mbind;
pub use self::linux_headers_asm_unistd::__NR_get_mempolicy;
pub use self::linux_headers_asm_unistd::__NR_set_mempolicy;
pub use self::linux_headers_asm_unistd::__NR_openat;
pub use self::linux_headers_asm_unistd::__NR_mkdirat;
pub use self::linux_headers_asm_unistd::__NR_mknodat;
pub use self::linux_headers_asm_unistd::__NR_fchownat;
pub use self::linux_headers_asm_unistd::__NR_futimesat;
pub use self::linux_headers_asm_unistd::__NR_fstatat64;
pub use self::linux_headers_asm_unistd::__NR_unlinkat;
pub use self::linux_headers_asm_unistd::__NR_renameat;
pub use self::linux_headers_asm_unistd::__NR_linkat;
pub use self::linux_headers_asm_unistd::__NR_symlinkat;
pub use self::linux_headers_asm_unistd::__NR_readlinkat;
pub use self::linux_headers_asm_unistd::__NR_fchmodat;
pub use self::linux_headers_asm_unistd::__NR_faccessat;
pub use self::linux_headers_asm_unistd::__NR_pselect6;
pub use self::linux_headers_asm_unistd::__NR_ppoll;
pub use self::linux_headers_asm_unistd::__NR_unshare;
pub use self::linux_headers_asm_unistd::__NR_set_robust_list;
pub use self::linux_headers_asm_unistd::__NR_get_robust_list;
pub use self::linux_headers_asm_unistd::__NR_splice;
pub use self::linux_headers_asm_unistd::__NR_arm_sync_file_range;
pub use self::linux_headers_asm_unistd::__NR_tee;
pub use self::linux_headers_asm_unistd::__NR_vmsplice;
pub use self::linux_headers_asm_unistd::__NR_move_pages;
pub use self::linux_headers_asm_unistd::__NR_getcpu;
pub use self::linux_headers_asm_unistd::__NR_epoll_pwait;
pub use self::linux_headers_asm_unistd::__NR_kexec_load;
pub use self::linux_headers_asm_unistd::__NR_utimensat;
pub use self::linux_headers_asm_unistd::__NR_signalfd;
pub use self::linux_headers_asm_unistd::__NR_timerfd_create;
pub use self::linux_headers_asm_unistd::__NR_eventfd;
pub use self::linux_headers_asm_unistd::__NR_fallocate;
pub use self::linux_headers_asm_unistd::__NR_timerfd_settime;
pub use self::linux_headers_asm_unistd::__NR_timerfd_gettime;
pub use self::linux_headers_asm_unistd::__NR_signalfd4;
pub use self::linux_headers_asm_unistd::__NR_eventfd2;
pub use self::linux_headers_asm_unistd::__NR_epoll_create1;
pub use self::linux_headers_asm_unistd::__NR_dup3;
pub use self::linux_headers_asm_unistd::__NR_pipe2;
pub use self::linux_headers_asm_unistd::__NR_inotify_init1;
pub use self::linux_headers_asm_unistd::__NR_preadv;
pub use self::linux_headers_asm_unistd::__NR_pwritev;
pub use self::linux_headers_asm_unistd::__NR_rt_tgsigqueueinfo;
pub use self::linux_headers_asm_unistd::__NR_perf_event_open;
pub use self::linux_headers_asm_unistd::__NR_recvmmsg;
pub use self::linux_headers_asm_unistd::__NR_accept4;
pub use self::linux_headers_asm_unistd::__NR_fanotify_init;
pub use self::linux_headers_asm_unistd::__NR_fanotify_mark;
pub use self::linux_headers_asm_unistd::__NR_prlimit64;
pub use self::linux_headers_asm_unistd::__NR_name_to_handle_at;
pub use self::linux_headers_asm_unistd::__NR_open_by_handle_at;
pub use self::linux_headers_asm_unistd::__NR_clock_adjtime;
pub use self::linux_headers_asm_unistd::__NR_syncfs;
pub use self::linux_headers_asm_unistd::__NR_sendmmsg;
pub use self::linux_headers_asm_unistd::__NR_setns;
pub use self::linux_headers_asm_unistd::__NR_process_vm_readv;
pub use self::linux_headers_asm_unistd::__NR_process_vm_writev;
pub use self::linux_headers_asm_unistd::__NR_kcmp;
pub use self::linux_headers_asm_unistd::__NR_finit_module;
pub use self::linux_headers_asm_unistd::__NR_sched_setattr;
pub use self::linux_headers_asm_unistd::__NR_sched_getattr;
pub use self::linux_headers_asm_unistd::__NR_renameat2;
pub use self::linux_headers_asm_unistd::__NR_seccomp;
pub use self::linux_headers_asm_unistd::__NR_getrandom;
pub use self::linux_headers_asm_unistd::__NR_memfd_create;
pub use self::linux_headers_asm_unistd::__NR_bpf;
pub use self::linux_headers_asm_unistd::__NR_execveat;
pub use self::linux_headers_asm_unistd::__NR_userfaultfd;
pub use self::linux_headers_asm_unistd::__NR_membarrier;
pub use self::linux_headers_asm_unistd::__NR_mlock2;
pub use self::linux_headers_asm_unistd::__NR_copy_file_range;
pub use self::linux_headers_asm_unistd::__NR_preadv2;
pub use self::linux_headers_asm_unistd::__NR_pwritev2;
pub use self::linux_headers_asm_unistd::__NR_pkey_mprotect;
pub use self::linux_headers_asm_unistd::__NR_pkey_alloc;
pub use self::linux_headers_asm_unistd::__NR_pkey_free;
pub use self::linux_headers_asm_unistd::__NR_statx;
pub use self::linux_headers_asm_unistd::__NR_rseq;
pub use self::linux_headers_asm_unistd::__NR_io_pgetevents;
pub use self::linux_headers_asm_unistd::__NR_migrate_pages;
pub use self::linux_headers_asm_unistd::__NR_kexec_file_load;
pub use self::linux_headers_asm_unistd::__NR_clock_gettime64;
pub use self::linux_headers_asm_unistd::__NR_clock_settime64;
pub use self::linux_headers_asm_unistd::__NR_clock_adjtime64;
pub use self::linux_headers_asm_unistd::__NR_clock_getres_time64;
pub use self::linux_headers_asm_unistd::__NR_clock_nanosleep_time64;
pub use self::linux_headers_asm_unistd::__NR_timer_gettime64;
pub use self::linux_headers_asm_unistd::__NR_timer_settime64;
pub use self::linux_headers_asm_unistd::__NR_timerfd_gettime64;
pub use self::linux_headers_asm_unistd::__NR_timerfd_settime64;
pub use self::linux_headers_asm_unistd::__NR_utimensat_time64;
pub use self::linux_headers_asm_unistd::__NR_pselect6_time64;
pub use self::linux_headers_asm_unistd::__NR_ppoll_time64;
pub use self::linux_headers_asm_unistd::__NR_io_pgetevents_time64;
pub use self::linux_headers_asm_unistd::__NR_recvmmsg_time64;
pub use self::linux_headers_asm_unistd::__NR_mq_timedsend_time64;
pub use self::linux_headers_asm_unistd::__NR_mq_timedreceive_time64;
pub use self::linux_headers_asm_unistd::__NR_semtimedop_time64;
pub use self::linux_headers_asm_unistd::__NR_rt_sigtimedwait_time64;
pub use self::linux_headers_asm_unistd::__NR_futex_time64;
pub use self::linux_headers_asm_unistd::__NR_sched_rr_get_interval_time64;
pub use self::linux_headers_asm_unistd::__NR_pidfd_send_signal;
pub use self::linux_headers_asm_unistd::__NR_io_uring_setup;
pub use self::linux_headers_asm_unistd::__NR_io_uring_enter;
pub use self::linux_headers_asm_unistd::__NR_io_uring_register;
pub use self::linux_headers_asm_unistd::__NR_open_tree;
pub use self::linux_headers_asm_unistd::__NR_move_mount;
pub use self::linux_headers_asm_unistd::__NR_fsopen;
pub use self::linux_headers_asm_unistd::__NR_fsconfig;
pub use self::linux_headers_asm_unistd::__NR_fsmount;
pub use self::linux_headers_asm_unistd::__NR_fspick;
pub use self::linux_headers_asm_unistd::__NR_pidfd_open;
pub use self::linux_headers_asm_unistd::__NR_clone3;
pub use self::linux_headers_asm_unistd::__NR_close_range;
pub use self::linux_headers_asm_unistd::__NR_openat2;
pub use self::linux_headers_asm_unistd::__NR_pidfd_getfd;
pub use self::linux_headers_asm_unistd::__NR_faccessat2;
pub use self::linux_headers_asm_unistd::__NR_process_madvise;
pub use self::linux_headers_asm_unistd::__NR_epoll_pwait2;
pub use self::linux_headers_asm_unistd::__NR_mount_setattr;
pub use self::linux_headers_asm_unistd::__NR_quotactl_fd;
pub use self::linux_headers_asm_unistd::__NR_landlock_create_ruleset;
pub use self::linux_headers_asm_unistd::__NR_landlock_add_rule;
pub use self::linux_headers_asm_unistd::__NR_landlock_restrict_self;
pub use self::linux_headers_asm_unistd::__NR_process_mrelease;
pub use self::linux_headers_asm_unistd::__NR_futex_waitv;
pub use self::linux_headers_asm_unistd::__NR_set_mempolicy_home_node;
pub use self::linux_headers_asm_unistd::__NR_cachestat;
pub use self::linux_headers_asm_unistd::__NR_fchmodat2;
pub use self::linux_headers_asm_unistd::__NR_map_shadow_stack;
pub use self::linux_headers_asm_unistd::__NR_futex_wake;
pub use self::linux_headers_asm_unistd::__NR_futex_wait;
pub use self::linux_headers_asm_unistd::__NR_futex_requeue;
pub use self::linux_headers_asm_unistd::__NR_statmount;
pub use self::linux_headers_asm_unistd::__NR_listmount;
pub use self::linux_headers_asm_unistd::__NR_lsm_get_self_attr;
pub use self::linux_headers_asm_unistd::__NR_lsm_set_self_attr;
pub use self::linux_headers_asm_unistd::__NR_lsm_list_modules;
pub use self::linux_headers_asm_unistd::__NR_mseal;
pub use self::linux_headers_asm_unistd::__NR_setxattrat;
pub use self::linux_headers_asm_unistd::__NR_getxattrat;
pub use self::linux_headers_asm_unistd::__NR_listxattrat;
pub use self::linux_headers_asm_unistd::__NR_removexattrat;
pub use self::linux_headers_asm_unistd::__NR_sync_file_range2;
mod linux_headers_linux_auxvec;
pub use self::linux_headers_linux_auxvec::AT_SYSINFO_EHDR;
pub use self::linux_headers_linux_auxvec::AT_NULL;
pub use self::linux_headers_linux_auxvec::AT_IGNORE;
pub use self::linux_headers_linux_auxvec::AT_EXECFD;
pub use self::linux_headers_linux_auxvec::AT_PHDR;
pub use self::linux_headers_linux_auxvec::AT_PHENT;
pub use self::linux_headers_linux_auxvec::AT_PHNUM;
pub use self::linux_headers_linux_auxvec::AT_PAGESZ;
pub use self::linux_headers_linux_auxvec::AT_BASE;
pub use self::linux_headers_linux_auxvec::AT_FLAGS;
pub use self::linux_headers_linux_auxvec::AT_ENTRY;
pub use self::linux_headers_linux_auxvec::AT_NOTELF;
pub use self::linux_headers_linux_auxvec::AT_UID;
pub use self::linux_headers_linux_auxvec::AT_EUID;
pub use self::linux_headers_linux_auxvec::AT_GID;
pub use self::linux_headers_linux_auxvec::AT_EGID;
pub use self::linux_headers_linux_auxvec::AT_PLATFORM;
pub use self::linux_headers_linux_auxvec::AT_HWCAP;
pub use self::linux_headers_linux_auxvec::AT_CLKTCK;
pub use self::linux_headers_linux_auxvec::AT_SECURE;
pub use self::linux_headers_linux_auxvec::AT_BASE_PLATFORM;
pub use self::linux_headers_linux_auxvec::AT_RANDOM;
pub use self::linux_headers_linux_auxvec::AT_HWCAP2;
pub use self::linux_headers_linux_auxvec::AT_RSEQ_FEATURE_SIZE;
pub use self::linux_headers_linux_auxvec::AT_RSEQ_ALIGN;
pub use self::linux_headers_linux_auxvec::AT_HWCAP3;
pub use self::linux_headers_linux_auxvec::AT_HWCAP4;
pub use self::linux_headers_linux_auxvec::AT_EXECFN;
pub use self::linux_headers_linux_auxvec::AT_MINSIGSTKSZ;
mod linux_headers_linux_prctl;
pub use self::linux_headers_linux_prctl::PR_SET_PDEATHSIG;
pub use self::linux_headers_linux_prctl::PR_GET_PDEATHSIG;
pub use self::linux_headers_linux_prctl::PR_GET_DUMPABLE;
pub use self::linux_headers_linux_prctl::PR_SET_DUMPABLE;
pub use self::linux_headers_linux_prctl::PR_GET_UNALIGN;
pub use self::linux_headers_linux_prctl::PR_SET_UNALIGN;
pub use self::linux_headers_linux_prctl::PR_UNALIGN_NOPRINT;
pub use self::linux_headers_linux_prctl::PR_UNALIGN_SIGBUS;
pub use self::linux_headers_linux_prctl::PR_GET_KEEPCAPS;
pub use self::linux_headers_linux_prctl::PR_SET_KEEPCAPS;
pub use self::linux_headers_linux_prctl::PR_GET_FPEMU;
pub use self::linux_headers_linux_prctl::PR_SET_FPEMU;
pub use self::linux_headers_linux_prctl::PR_FPEMU_NOPRINT;
pub use self::linux_headers_linux_prctl::PR_FPEMU_SIGFPE;
pub use self::linux_headers_linux_prctl::PR_GET_FPEXC;
pub use self::linux_headers_linux_prctl::PR_SET_FPEXC;
pub use self::linux_headers_linux_prctl::PR_FP_EXC_SW_ENABLE;
pub use self::linux_headers_linux_prctl::PR_FP_EXC_DIV;
pub use self::linux_headers_linux_prctl::PR_FP_EXC_OVF;
pub use self::linux_headers_linux_prctl::PR_FP_EXC_UND;
pub use self::linux_headers_linux_prctl::PR_FP_EXC_RES;
pub use self::linux_headers_linux_prctl::PR_FP_EXC_INV;
pub use self::linux_headers_linux_prctl::PR_FP_EXC_DISABLED;
pub use self::linux_headers_linux_prctl::PR_FP_EXC_NONRECOV;
pub use self::linux_headers_linux_prctl::PR_FP_EXC_ASYNC;
pub use self::linux_headers_linux_prctl::PR_FP_EXC_PRECISE;
pub use self::linux_headers_linux_prctl::PR_GET_TIMING;
pub use self::linux_headers_linux_prctl::PR_SET_TIMING;
pub use self::linux_headers_linux_prctl::PR_TIMING_STATISTICAL;
pub use self::linux_headers_linux_prctl::PR_TIMING_TIMESTAMP;
pub use self::linux_headers_linux_prctl::PR_SET_NAME;
pub use self::linux_headers_linux_prctl::PR_GET_NAME;
pub use self::linux_headers_linux_prctl::PR_GET_ENDIAN;
pub use self::linux_headers_linux_prctl::PR_SET_ENDIAN;
pub use self::linux_headers_linux_prctl::PR_ENDIAN_BIG;
pub use self::linux_headers_linux_prctl::PR_ENDIAN_LITTLE;
pub use self::linux_headers_linux_prctl::PR_ENDIAN_PPC_LITTLE;
pub use self::linux_headers_linux_prctl::PR_GET_SECCOMP;
pub use self::linux_headers_linux_prctl::PR_SET_SECCOMP;
pub use self::linux_headers_linux_prctl::PR_CAPBSET_READ;
pub use self::linux_headers_linux_prctl::PR_CAPBSET_DROP;
pub use self::linux_headers_linux_prctl::PR_GET_TSC;
pub use self::linux_headers_linux_prctl::PR_SET_TSC;
pub use self::linux_headers_linux_prctl::PR_TSC_ENABLE;
pub use self::linux_headers_linux_prctl::PR_TSC_SIGSEGV;
pub use self::linux_headers_linux_prctl::PR_GET_SECUREBITS;
pub use self::linux_headers_linux_prctl::PR_SET_SECUREBITS;
pub use self::linux_headers_linux_prctl::PR_SET_TIMERSLACK;
pub use self::linux_headers_linux_prctl::PR_GET_TIMERSLACK;
pub use self::linux_headers_linux_prctl::PR_TASK_PERF_EVENTS_DISABLE;
pub use self::linux_headers_linux_prctl::PR_TASK_PERF_EVENTS_ENABLE;
pub use self::linux_headers_linux_prctl::PR_MCE_KILL;
pub use self::linux_headers_linux_prctl::PR_MCE_KILL_CLEAR;
pub use self::linux_headers_linux_prctl::PR_MCE_KILL_SET;
pub use self::linux_headers_linux_prctl::PR_MCE_KILL_LATE;
pub use self::linux_headers_linux_prctl::PR_MCE_KILL_EARLY;
pub use self::linux_headers_linux_prctl::PR_MCE_KILL_DEFAULT;
pub use self::linux_headers_linux_prctl::PR_MCE_KILL_GET;
pub use self::linux_headers_linux_prctl::PR_SET_MM;
pub use self::linux_headers_linux_prctl::PR_SET_MM_START_CODE;
pub use self::linux_headers_linux_prctl::PR_SET_MM_END_CODE;
pub use self::linux_headers_linux_prctl::PR_SET_MM_START_DATA;
pub use self::linux_headers_linux_prctl::PR_SET_MM_END_DATA;
pub use self::linux_headers_linux_prctl::PR_SET_MM_START_STACK;
pub use self::linux_headers_linux_prctl::PR_SET_MM_START_BRK;
pub use self::linux_headers_linux_prctl::PR_SET_MM_BRK;
pub use self::linux_headers_linux_prctl::PR_SET_MM_ARG_START;
pub use self::linux_headers_linux_prctl::PR_SET_MM_ARG_END;
pub use self::linux_headers_linux_prctl::PR_SET_MM_ENV_START;
pub use self::linux_headers_linux_prctl::PR_SET_MM_ENV_END;
pub use self::linux_headers_linux_prctl::PR_SET_MM_AUXV;
pub use self::linux_headers_linux_prctl::PR_SET_MM_EXE_FILE;
pub use self::linux_headers_linux_prctl::PR_SET_MM_MAP;
pub use self::linux_headers_linux_prctl::PR_SET_MM_MAP_SIZE;
pub use self::linux_headers_linux_prctl::PR_SET_PTRACER;
pub use self::linux_headers_linux_prctl::PR_SET_PTRACER_ANY;
pub use self::linux_headers_linux_prctl::PR_SET_CHILD_SUBREAPER;
pub use self::linux_headers_linux_prctl::PR_GET_CHILD_SUBREAPER;
pub use self::linux_headers_linux_prctl::PR_SET_NO_NEW_PRIVS;
pub use self::linux_headers_linux_prctl::PR_GET_NO_NEW_PRIVS;
pub use self::linux_headers_linux_prctl::PR_GET_TID_ADDRESS;
pub use self::linux_headers_linux_prctl::PR_SET_THP_DISABLE;
pub use self::linux_headers_linux_prctl::PR_GET_THP_DISABLE;
pub use self::linux_headers_linux_prctl::PR_MPX_ENABLE_MANAGEMENT;
pub use self::linux_headers_linux_prctl::PR_MPX_DISABLE_MANAGEMENT;
pub use self::linux_headers_linux_prctl::PR_SET_FP_MODE;
pub use self::linux_headers_linux_prctl::PR_GET_FP_MODE;
pub use self::linux_headers_linux_prctl::PR_FP_MODE_FR;
pub use self::linux_headers_linux_prctl::PR_FP_MODE_FRE;
pub use self::linux_headers_linux_prctl::PR_CAP_AMBIENT;
pub use self::linux_headers_linux_prctl::PR_CAP_AMBIENT_IS_SET;
pub use self::linux_headers_linux_prctl::PR_CAP_AMBIENT_RAISE;
pub use self::linux_headers_linux_prctl::PR_CAP_AMBIENT_LOWER;
pub use self::linux_headers_linux_prctl::PR_CAP_AMBIENT_CLEAR_ALL;
pub use self::linux_headers_linux_prctl::PR_SVE_SET_VL;
pub use self::linux_headers_linux_prctl::PR_SVE_SET_VL_ONEXEC;
pub use self::linux_headers_linux_prctl::PR_SVE_GET_VL;
pub use self::linux_headers_linux_prctl::PR_SVE_VL_LEN_MASK;
pub use self::linux_headers_linux_prctl::PR_SVE_VL_INHERIT;
pub use self::linux_headers_linux_prctl::PR_GET_SPECULATION_CTRL;
pub use self::linux_headers_linux_prctl::PR_SET_SPECULATION_CTRL;
pub use self::linux_headers_linux_prctl::PR_SPEC_STORE_BYPASS;
pub use self::linux_headers_linux_prctl::PR_SPEC_INDIRECT_BRANCH;
pub use self::linux_headers_linux_prctl::PR_SPEC_L1D_FLUSH;
pub use self::linux_headers_linux_prctl::PR_SPEC_NOT_AFFECTED;
pub use self::linux_headers_linux_prctl::PR_SPEC_PRCTL;
pub use self::linux_headers_linux_prctl::PR_SPEC_ENABLE;
pub use self::linux_headers_linux_prctl::PR_SPEC_DISABLE;
pub use self::linux_headers_linux_prctl::PR_SPEC_FORCE_DISABLE;
pub use self::linux_headers_linux_prctl::PR_SPEC_DISABLE_NOEXEC;
pub use self::linux_headers_linux_prctl::PR_PAC_RESET_KEYS;
pub use self::linux_headers_linux_prctl::PR_PAC_APIAKEY;
pub use self::linux_headers_linux_prctl::PR_PAC_APIBKEY;
pub use self::linux_headers_linux_prctl::PR_PAC_APDAKEY;
pub use self::linux_headers_linux_prctl::PR_PAC_APDBKEY;
pub use self::linux_headers_linux_prctl::PR_PAC_APGAKEY;
pub use self::linux_headers_linux_prctl::PR_SET_TAGGED_ADDR_CTRL;
pub use self::linux_headers_linux_prctl::PR_GET_TAGGED_ADDR_CTRL;
pub use self::linux_headers_linux_prctl::PR_TAGGED_ADDR_ENABLE;
pub use self::linux_headers_linux_prctl::PR_MTE_TCF_NONE;
pub use self::linux_headers_linux_prctl::PR_MTE_TCF_SYNC;
pub use self::linux_headers_linux_prctl::PR_MTE_TCF_ASYNC;
pub use self::linux_headers_linux_prctl::PR_MTE_TCF_MASK;
pub use self::linux_headers_linux_prctl::PR_MTE_TAG_SHIFT;
pub use self::linux_headers_linux_prctl::PR_MTE_TAG_MASK;
pub use self::linux_headers_linux_prctl::PR_MTE_TCF_SHIFT;
pub use self::linux_headers_linux_prctl::PR_PMLEN_SHIFT;
pub use self::linux_headers_linux_prctl::PR_PMLEN_MASK;
pub use self::linux_headers_linux_prctl::PR_SET_IO_FLUSHER;
pub use self::linux_headers_linux_prctl::PR_GET_IO_FLUSHER;
pub use self::linux_headers_linux_prctl::PR_SET_SYSCALL_USER_DISPATCH;
pub use self::linux_headers_linux_prctl::PR_SYS_DISPATCH_OFF;
pub use self::linux_headers_linux_prctl::PR_SYS_DISPATCH_ON;
pub use self::linux_headers_linux_prctl::PR_PAC_SET_ENABLED_KEYS;
pub use self::linux_headers_linux_prctl::PR_PAC_GET_ENABLED_KEYS;
pub use self::linux_headers_linux_prctl::PR_SCHED_CORE;
pub use self::linux_headers_linux_prctl::PR_SCHED_CORE_GET;
pub use self::linux_headers_linux_prctl::PR_SCHED_CORE_CREATE;
pub use self::linux_headers_linux_prctl::PR_SCHED_CORE_SHARE_TO;
pub use self::linux_headers_linux_prctl::PR_SCHED_CORE_SHARE_FROM;
pub use self::linux_headers_linux_prctl::PR_SCHED_CORE_MAX;
pub use self::linux_headers_linux_prctl::PR_SCHED_CORE_SCOPE_THREAD;
pub use self::linux_headers_linux_prctl::PR_SCHED_CORE_SCOPE_THREAD_GROUP;
pub use self::linux_headers_linux_prctl::PR_SCHED_CORE_SCOPE_PROCESS_GROUP;
pub use self::linux_headers_linux_prctl::PR_SME_SET_VL;
pub use self::linux_headers_linux_prctl::PR_SME_SET_VL_ONEXEC;
pub use self::linux_headers_linux_prctl::PR_SME_GET_VL;
pub use self::linux_headers_linux_prctl::PR_SME_VL_LEN_MASK;
pub use self::linux_headers_linux_prctl::PR_SME_VL_INHERIT;
pub use self::linux_headers_linux_prctl::PR_SET_MDWE;
pub use self::linux_headers_linux_prctl::PR_MDWE_REFUSE_EXEC_GAIN;
pub use self::linux_headers_linux_prctl::PR_MDWE_NO_INHERIT;
pub use self::linux_headers_linux_prctl::PR_GET_MDWE;
pub use self::linux_headers_linux_prctl::PR_SET_VMA;
pub use self::linux_headers_linux_prctl::PR_SET_VMA_ANON_NAME;
pub use self::linux_headers_linux_prctl::PR_GET_AUXV;
pub use self::linux_headers_linux_prctl::PR_SET_MEMORY_MERGE;
pub use self::linux_headers_linux_prctl::PR_GET_MEMORY_MERGE;
pub use self::linux_headers_linux_prctl::PR_RISCV_V_SET_CONTROL;
pub use self::linux_headers_linux_prctl::PR_RISCV_V_GET_CONTROL;
pub use self::linux_headers_linux_prctl::PR_RISCV_V_VSTATE_CTRL_DEFAULT;
pub use self::linux_headers_linux_prctl::PR_RISCV_V_VSTATE_CTRL_OFF;
pub use self::linux_headers_linux_prctl::PR_RISCV_V_VSTATE_CTRL_ON;
pub use self::linux_headers_linux_prctl::PR_RISCV_V_VSTATE_CTRL_INHERIT;
pub use self::linux_headers_linux_prctl::PR_RISCV_V_VSTATE_CTRL_CUR_MASK;
pub use self::linux_headers_linux_prctl::PR_RISCV_V_VSTATE_CTRL_NEXT_MASK;
pub use self::linux_headers_linux_prctl::PR_RISCV_V_VSTATE_CTRL_MASK;
pub use self::linux_headers_linux_prctl::PR_RISCV_SET_ICACHE_FLUSH_CTX;
pub use self::linux_headers_linux_prctl::PR_RISCV_CTX_SW_FENCEI_ON;
pub use self::linux_headers_linux_prctl::PR_RISCV_CTX_SW_FENCEI_OFF;
pub use self::linux_headers_linux_prctl::PR_RISCV_SCOPE_PER_PROCESS;
pub use self::linux_headers_linux_prctl::PR_RISCV_SCOPE_PER_THREAD;
pub use self::linux_headers_linux_prctl::PR_PPC_GET_DEXCR;
pub use self::linux_headers_linux_prctl::PR_PPC_SET_DEXCR;
pub use self::linux_headers_linux_prctl::PR_PPC_DEXCR_SBHE;
pub use self::linux_headers_linux_prctl::PR_PPC_DEXCR_IBRTPD;
pub use self::linux_headers_linux_prctl::PR_PPC_DEXCR_SRAPD;
pub use self::linux_headers_linux_prctl::PR_PPC_DEXCR_NPHIE;
pub use self::linux_headers_linux_prctl::PR_PPC_DEXCR_CTRL_EDITABLE;
pub use self::linux_headers_linux_prctl::PR_PPC_DEXCR_CTRL_SET;
pub use self::linux_headers_linux_prctl::PR_PPC_DEXCR_CTRL_CLEAR;
pub use self::linux_headers_linux_prctl::PR_PPC_DEXCR_CTRL_SET_ONEXEC;
pub use self::linux_headers_linux_prctl::PR_PPC_DEXCR_CTRL_CLEAR_ONEXEC;
pub use self::linux_headers_linux_prctl::PR_PPC_DEXCR_CTRL_MASK;
pub use self::linux_headers_linux_prctl::PR_GET_SHADOW_STACK_STATUS;
pub use self::linux_headers_linux_prctl::PR_SET_SHADOW_STACK_STATUS;
pub use self::linux_headers_linux_prctl::PR_SHADOW_STACK_ENABLE;
pub use self::linux_headers_linux_prctl::PR_SHADOW_STACK_WRITE;
pub use self::linux_headers_linux_prctl::PR_SHADOW_STACK_PUSH;
pub use self::linux_headers_linux_prctl::PR_LOCK_SHADOW_STACK_STATUS;
mod dlfcn;
pub use self::dlfcn::RTLD_DEFAULT;
pub use self::dlfcn::dlsym;
mod elf;
pub use self::elf::Elf32_auxv_t;
pub use self::elf::Elf64_auxv_t;
mod sys_auxv;
pub use self::sys_auxv::getauxval;
mod unistd;
pub use self::unistd::syscall;
pub type c_char = u8;

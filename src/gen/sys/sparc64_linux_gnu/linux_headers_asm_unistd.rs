// SPDX-License-Identifier: Apache-2.0 OR MIT
// This file is @generated by test-helper-internal-codegen
// (generate function at tools/codegen/src/ffi.rs).
// It is not intended for manual editing.

#![cfg_attr(rustfmt, rustfmt::skip)]

pub const __NR_restart_syscall: u32 = 0;
pub const __NR_exit: u32 = 1;
pub const __NR_fork: u32 = 2;
pub const __NR_read: u32 = 3;
pub const __NR_write: u32 = 4;
pub const __NR_open: u32 = 5;
pub const __NR_close: u32 = 6;
pub const __NR_wait4: u32 = 7;
pub const __NR_creat: u32 = 8;
pub const __NR_link: u32 = 9;
pub const __NR_unlink: u32 = 10;
pub const __NR_execv: u32 = 11;
pub const __NR_chdir: u32 = 12;
pub const __NR_chown: u32 = 13;
pub const __NR_mknod: u32 = 14;
pub const __NR_chmod: u32 = 15;
pub const __NR_lchown: u32 = 16;
pub const __NR_brk: u32 = 17;
pub const __NR_perfctr: u32 = 18;
pub const __NR_lseek: u32 = 19;
pub const __NR_getpid: u32 = 20;
pub const __NR_capget: u32 = 21;
pub const __NR_capset: u32 = 22;
pub const __NR_setuid: u32 = 23;
pub const __NR_getuid: u32 = 24;
pub const __NR_vmsplice: u32 = 25;
pub const __NR_ptrace: u32 = 26;
pub const __NR_alarm: u32 = 27;
pub const __NR_sigaltstack: u32 = 28;
pub const __NR_pause: u32 = 29;
pub const __NR_utime: u32 = 30;
pub const __NR_access: u32 = 33;
pub const __NR_nice: u32 = 34;
pub const __NR_sync: u32 = 36;
pub const __NR_kill: u32 = 37;
pub const __NR_stat: u32 = 38;
pub const __NR_sendfile: u32 = 39;
pub const __NR_lstat: u32 = 40;
pub const __NR_dup: u32 = 41;
pub const __NR_pipe: u32 = 42;
pub const __NR_times: u32 = 43;
pub const __NR_umount2: u32 = 45;
pub const __NR_setgid: u32 = 46;
pub const __NR_getgid: u32 = 47;
pub const __NR_signal: u32 = 48;
pub const __NR_geteuid: u32 = 49;
pub const __NR_getegid: u32 = 50;
pub const __NR_acct: u32 = 51;
pub const __NR_memory_ordering: u32 = 52;
pub const __NR_ioctl: u32 = 54;
pub const __NR_reboot: u32 = 55;
pub const __NR_symlink: u32 = 57;
pub const __NR_readlink: u32 = 58;
pub const __NR_execve: u32 = 59;
pub const __NR_umask: u32 = 60;
pub const __NR_chroot: u32 = 61;
pub const __NR_fstat: u32 = 62;
pub const __NR_fstat64: u32 = 63;
pub const __NR_getpagesize: u32 = 64;
pub const __NR_msync: u32 = 65;
pub const __NR_vfork: u32 = 66;
pub const __NR_pread64: u32 = 67;
pub const __NR_pwrite64: u32 = 68;
pub const __NR_mmap: u32 = 71;
pub const __NR_munmap: u32 = 73;
pub const __NR_mprotect: u32 = 74;
pub const __NR_madvise: u32 = 75;
pub const __NR_vhangup: u32 = 76;
pub const __NR_mincore: u32 = 78;
pub const __NR_getgroups: u32 = 79;
pub const __NR_setgroups: u32 = 80;
pub const __NR_getpgrp: u32 = 81;
pub const __NR_setitimer: u32 = 83;
pub const __NR_swapon: u32 = 85;
pub const __NR_getitimer: u32 = 86;
pub const __NR_sethostname: u32 = 88;
pub const __NR_dup2: u32 = 90;
pub const __NR_fcntl: u32 = 92;
pub const __NR_select: u32 = 93;
pub const __NR_fsync: u32 = 95;
pub const __NR_setpriority: u32 = 96;
pub const __NR_socket: u32 = 97;
pub const __NR_connect: u32 = 98;
pub const __NR_accept: u32 = 99;
pub const __NR_getpriority: u32 = 100;
pub const __NR_rt_sigreturn: u32 = 101;
pub const __NR_rt_sigaction: u32 = 102;
pub const __NR_rt_sigprocmask: u32 = 103;
pub const __NR_rt_sigpending: u32 = 104;
pub const __NR_rt_sigtimedwait: u32 = 105;
pub const __NR_rt_sigqueueinfo: u32 = 106;
pub const __NR_rt_sigsuspend: u32 = 107;
pub const __NR_setresuid: u32 = 108;
pub const __NR_getresuid: u32 = 109;
pub const __NR_setresgid: u32 = 110;
pub const __NR_getresgid: u32 = 111;
pub const __NR_recvmsg: u32 = 113;
pub const __NR_sendmsg: u32 = 114;
pub const __NR_gettimeofday: u32 = 116;
pub const __NR_getrusage: u32 = 117;
pub const __NR_getsockopt: u32 = 118;
pub const __NR_getcwd: u32 = 119;
pub const __NR_readv: u32 = 120;
pub const __NR_writev: u32 = 121;
pub const __NR_settimeofday: u32 = 122;
pub const __NR_fchown: u32 = 123;
pub const __NR_fchmod: u32 = 124;
pub const __NR_recvfrom: u32 = 125;
pub const __NR_setreuid: u32 = 126;
pub const __NR_setregid: u32 = 127;
pub const __NR_rename: u32 = 128;
pub const __NR_truncate: u32 = 129;
pub const __NR_ftruncate: u32 = 130;
pub const __NR_flock: u32 = 131;
pub const __NR_lstat64: u32 = 132;
pub const __NR_sendto: u32 = 133;
pub const __NR_shutdown: u32 = 134;
pub const __NR_socketpair: u32 = 135;
pub const __NR_mkdir: u32 = 136;
pub const __NR_rmdir: u32 = 137;
pub const __NR_utimes: u32 = 138;
pub const __NR_stat64: u32 = 139;
pub const __NR_sendfile64: u32 = 140;
pub const __NR_getpeername: u32 = 141;
pub const __NR_futex: u32 = 142;
pub const __NR_gettid: u32 = 143;
pub const __NR_getrlimit: u32 = 144;
pub const __NR_setrlimit: u32 = 145;
pub const __NR_pivot_root: u32 = 146;
pub const __NR_prctl: u32 = 147;
pub const __NR_pciconfig_read: u32 = 148;
pub const __NR_pciconfig_write: u32 = 149;
pub const __NR_getsockname: u32 = 150;
pub const __NR_inotify_init: u32 = 151;
pub const __NR_inotify_add_watch: u32 = 152;
pub const __NR_poll: u32 = 153;
pub const __NR_getdents64: u32 = 154;
pub const __NR_inotify_rm_watch: u32 = 156;
pub const __NR_statfs: u32 = 157;
pub const __NR_fstatfs: u32 = 158;
pub const __NR_umount: u32 = 159;
pub const __NR_sched_set_affinity: u32 = 160;
pub const __NR_sched_get_affinity: u32 = 161;
pub const __NR_getdomainname: u32 = 162;
pub const __NR_setdomainname: u32 = 163;
pub const __NR_utrap_install: u32 = 164;
pub const __NR_quotactl: u32 = 165;
pub const __NR_set_tid_address: u32 = 166;
pub const __NR_mount: u32 = 167;
pub const __NR_ustat: u32 = 168;
pub const __NR_setxattr: u32 = 169;
pub const __NR_lsetxattr: u32 = 170;
pub const __NR_fsetxattr: u32 = 171;
pub const __NR_getxattr: u32 = 172;
pub const __NR_lgetxattr: u32 = 173;
pub const __NR_getdents: u32 = 174;
pub const __NR_setsid: u32 = 175;
pub const __NR_fchdir: u32 = 176;
pub const __NR_fgetxattr: u32 = 177;
pub const __NR_listxattr: u32 = 178;
pub const __NR_llistxattr: u32 = 179;
pub const __NR_flistxattr: u32 = 180;
pub const __NR_removexattr: u32 = 181;
pub const __NR_lremovexattr: u32 = 182;
pub const __NR_sigpending: u32 = 183;
pub const __NR_query_module: u32 = 184;
pub const __NR_setpgid: u32 = 185;
pub const __NR_fremovexattr: u32 = 186;
pub const __NR_tkill: u32 = 187;
pub const __NR_exit_group: u32 = 188;
pub const __NR_uname: u32 = 189;
pub const __NR_init_module: u32 = 190;
pub const __NR_personality: u32 = 191;
pub const __NR_remap_file_pages: u32 = 192;
pub const __NR_epoll_create: u32 = 193;
pub const __NR_epoll_ctl: u32 = 194;
pub const __NR_epoll_wait: u32 = 195;
pub const __NR_ioprio_set: u32 = 196;
pub const __NR_getppid: u32 = 197;
pub const __NR_sigaction: u32 = 198;
pub const __NR_sgetmask: u32 = 199;
pub const __NR_ssetmask: u32 = 200;
pub const __NR_sigsuspend: u32 = 201;
pub const __NR_oldlstat: u32 = 202;
pub const __NR_uselib: u32 = 203;
pub const __NR_readdir: u32 = 204;
pub const __NR_readahead: u32 = 205;
pub const __NR_socketcall: u32 = 206;
pub const __NR_syslog: u32 = 207;
pub const __NR_lookup_dcookie: u32 = 208;
pub const __NR_fadvise64: u32 = 209;
pub const __NR_fadvise64_64: u32 = 210;
pub const __NR_tgkill: u32 = 211;
pub const __NR_waitpid: u32 = 212;
pub const __NR_swapoff: u32 = 213;
pub const __NR_sysinfo: u32 = 214;
pub const __NR_ipc: u32 = 215;
pub const __NR_sigreturn: u32 = 216;
pub const __NR_clone: u32 = 217;
pub const __NR_ioprio_get: u32 = 218;
pub const __NR_adjtimex: u32 = 219;
pub const __NR_sigprocmask: u32 = 220;
pub const __NR_create_module: u32 = 221;
pub const __NR_delete_module: u32 = 222;
pub const __NR_get_kernel_syms: u32 = 223;
pub const __NR_getpgid: u32 = 224;
pub const __NR_bdflush: u32 = 225;
pub const __NR_sysfs: u32 = 226;
pub const __NR_afs_syscall: u32 = 227;
pub const __NR_setfsuid: u32 = 228;
pub const __NR_setfsgid: u32 = 229;
pub const __NR__newselect: u32 = 230;
pub const __NR_splice: u32 = 232;
pub const __NR_stime: u32 = 233;
pub const __NR_statfs64: u32 = 234;
pub const __NR_fstatfs64: u32 = 235;
pub const __NR__llseek: u32 = 236;
pub const __NR_mlock: u32 = 237;
pub const __NR_munlock: u32 = 238;
pub const __NR_mlockall: u32 = 239;
pub const __NR_munlockall: u32 = 240;
pub const __NR_sched_setparam: u32 = 241;
pub const __NR_sched_getparam: u32 = 242;
pub const __NR_sched_setscheduler: u32 = 243;
pub const __NR_sched_getscheduler: u32 = 244;
pub const __NR_sched_yield: u32 = 245;
pub const __NR_sched_get_priority_max: u32 = 246;
pub const __NR_sched_get_priority_min: u32 = 247;
pub const __NR_sched_rr_get_interval: u32 = 248;
pub const __NR_nanosleep: u32 = 249;
pub const __NR_mremap: u32 = 250;
pub const __NR__sysctl: u32 = 251;
pub const __NR_getsid: u32 = 252;
pub const __NR_fdatasync: u32 = 253;
pub const __NR_nfsservctl: u32 = 254;
pub const __NR_sync_file_range: u32 = 255;
pub const __NR_clock_settime: u32 = 256;
pub const __NR_clock_gettime: u32 = 257;
pub const __NR_clock_getres: u32 = 258;
pub const __NR_clock_nanosleep: u32 = 259;
pub const __NR_sched_getaffinity: u32 = 260;
pub const __NR_sched_setaffinity: u32 = 261;
pub const __NR_timer_settime: u32 = 262;
pub const __NR_timer_gettime: u32 = 263;
pub const __NR_timer_getoverrun: u32 = 264;
pub const __NR_timer_delete: u32 = 265;
pub const __NR_timer_create: u32 = 266;
pub const __NR_vserver: u32 = 267;
pub const __NR_io_setup: u32 = 268;
pub const __NR_io_destroy: u32 = 269;
pub const __NR_io_submit: u32 = 270;
pub const __NR_io_cancel: u32 = 271;
pub const __NR_io_getevents: u32 = 272;
pub const __NR_mq_open: u32 = 273;
pub const __NR_mq_unlink: u32 = 274;
pub const __NR_mq_timedsend: u32 = 275;
pub const __NR_mq_timedreceive: u32 = 276;
pub const __NR_mq_notify: u32 = 277;
pub const __NR_mq_getsetattr: u32 = 278;
pub const __NR_waitid: u32 = 279;
pub const __NR_tee: u32 = 280;
pub const __NR_add_key: u32 = 281;
pub const __NR_request_key: u32 = 282;
pub const __NR_keyctl: u32 = 283;
pub const __NR_openat: u32 = 284;
pub const __NR_mkdirat: u32 = 285;
pub const __NR_mknodat: u32 = 286;
pub const __NR_fchownat: u32 = 287;
pub const __NR_futimesat: u32 = 288;
pub const __NR_fstatat64: u32 = 289;
pub const __NR_unlinkat: u32 = 290;
pub const __NR_renameat: u32 = 291;
pub const __NR_linkat: u32 = 292;
pub const __NR_symlinkat: u32 = 293;
pub const __NR_readlinkat: u32 = 294;
pub const __NR_fchmodat: u32 = 295;
pub const __NR_faccessat: u32 = 296;
pub const __NR_pselect6: u32 = 297;
pub const __NR_ppoll: u32 = 298;
pub const __NR_unshare: u32 = 299;
pub const __NR_set_robust_list: u32 = 300;
pub const __NR_get_robust_list: u32 = 301;
pub const __NR_migrate_pages: u32 = 302;
pub const __NR_mbind: u32 = 303;
pub const __NR_get_mempolicy: u32 = 304;
pub const __NR_set_mempolicy: u32 = 305;
pub const __NR_kexec_load: u32 = 306;
pub const __NR_move_pages: u32 = 307;
pub const __NR_getcpu: u32 = 308;
pub const __NR_epoll_pwait: u32 = 309;
pub const __NR_utimensat: u32 = 310;
pub const __NR_signalfd: u32 = 311;
pub const __NR_timerfd_create: u32 = 312;
pub const __NR_eventfd: u32 = 313;
pub const __NR_fallocate: u32 = 314;
pub const __NR_timerfd_settime: u32 = 315;
pub const __NR_timerfd_gettime: u32 = 316;
pub const __NR_signalfd4: u32 = 317;
pub const __NR_eventfd2: u32 = 318;
pub const __NR_epoll_create1: u32 = 319;
pub const __NR_dup3: u32 = 320;
pub const __NR_pipe2: u32 = 321;
pub const __NR_inotify_init1: u32 = 322;
pub const __NR_accept4: u32 = 323;
pub const __NR_preadv: u32 = 324;
pub const __NR_pwritev: u32 = 325;
pub const __NR_rt_tgsigqueueinfo: u32 = 326;
pub const __NR_perf_event_open: u32 = 327;
pub const __NR_recvmmsg: u32 = 328;
pub const __NR_fanotify_init: u32 = 329;
pub const __NR_fanotify_mark: u32 = 330;
pub const __NR_prlimit64: u32 = 331;
pub const __NR_name_to_handle_at: u32 = 332;
pub const __NR_open_by_handle_at: u32 = 333;
pub const __NR_clock_adjtime: u32 = 334;
pub const __NR_syncfs: u32 = 335;
pub const __NR_sendmmsg: u32 = 336;
pub const __NR_setns: u32 = 337;
pub const __NR_process_vm_readv: u32 = 338;
pub const __NR_process_vm_writev: u32 = 339;
pub const __NR_kern_features: u32 = 340;
pub const __NR_kcmp: u32 = 341;
pub const __NR_finit_module: u32 = 342;
pub const __NR_sched_setattr: u32 = 343;
pub const __NR_sched_getattr: u32 = 344;
pub const __NR_renameat2: u32 = 345;
pub const __NR_seccomp: u32 = 346;
pub const __NR_getrandom: u32 = 347;
pub const __NR_memfd_create: u32 = 348;
pub const __NR_bpf: u32 = 349;
pub const __NR_execveat: u32 = 350;
pub const __NR_membarrier: u32 = 351;
pub const __NR_userfaultfd: u32 = 352;
pub const __NR_bind: u32 = 353;
pub const __NR_listen: u32 = 354;
pub const __NR_setsockopt: u32 = 355;
pub const __NR_mlock2: u32 = 356;
pub const __NR_copy_file_range: u32 = 357;
pub const __NR_preadv2: u32 = 358;
pub const __NR_pwritev2: u32 = 359;
pub const __NR_statx: u32 = 360;
pub const __NR_io_pgetevents: u32 = 361;
pub const __NR_pkey_mprotect: u32 = 362;
pub const __NR_pkey_alloc: u32 = 363;
pub const __NR_pkey_free: u32 = 364;
pub const __NR_rseq: u32 = 365;
pub const __NR_semtimedop: u32 = 392;
pub const __NR_semget: u32 = 393;
pub const __NR_semctl: u32 = 394;
pub const __NR_shmget: u32 = 395;
pub const __NR_shmctl: u32 = 396;
pub const __NR_shmat: u32 = 397;
pub const __NR_shmdt: u32 = 398;
pub const __NR_msgget: u32 = 399;
pub const __NR_msgsnd: u32 = 400;
pub const __NR_msgrcv: u32 = 401;
pub const __NR_msgctl: u32 = 402;
pub const __NR_pidfd_send_signal: u32 = 424;
pub const __NR_io_uring_setup: u32 = 425;
pub const __NR_io_uring_enter: u32 = 426;
pub const __NR_io_uring_register: u32 = 427;
pub const __NR_open_tree: u32 = 428;
pub const __NR_move_mount: u32 = 429;
pub const __NR_fsopen: u32 = 430;
pub const __NR_fsconfig: u32 = 431;
pub const __NR_fsmount: u32 = 432;
pub const __NR_fspick: u32 = 433;
pub const __NR_pidfd_open: u32 = 434;
pub const __NR_close_range: u32 = 436;
pub const __NR_openat2: u32 = 437;
pub const __NR_pidfd_getfd: u32 = 438;
pub const __NR_faccessat2: u32 = 439;
pub const __NR_process_madvise: u32 = 440;
pub const __NR_epoll_pwait2: u32 = 441;
pub const __NR_mount_setattr: u32 = 442;
pub const __NR_quotactl_fd: u32 = 443;
pub const __NR_landlock_create_ruleset: u32 = 444;
pub const __NR_landlock_add_rule: u32 = 445;
pub const __NR_landlock_restrict_self: u32 = 446;
pub const __NR_process_mrelease: u32 = 448;
pub const __NR_futex_waitv: u32 = 449;
pub const __NR_set_mempolicy_home_node: u32 = 450;
pub const __NR_cachestat: u32 = 451;
pub const __NR_fchmodat2: u32 = 452;
pub const __NR_map_shadow_stack: u32 = 453;
pub const __NR_futex_wake: u32 = 454;
pub const __NR_futex_wait: u32 = 455;
pub const __NR_futex_requeue: u32 = 456;
pub const __NR_statmount: u32 = 457;
pub const __NR_listmount: u32 = 458;
pub const __NR_lsm_get_self_attr: u32 = 459;
pub const __NR_lsm_set_self_attr: u32 = 460;
pub const __NR_lsm_list_modules: u32 = 461;
pub const __NR_mseal: u32 = 462;
pub const __NR_setxattrat: u32 = 463;
pub const __NR_getxattrat: u32 = 464;
pub const __NR_listxattrat: u32 = 465;
pub const __NR_removexattrat: u32 = 466;
pub const __NR_open_tree_attr: u32 = 467;

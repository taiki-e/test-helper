// SPDX-License-Identifier: Apache-2.0 OR MIT
// This file is @generated by test-helper-internal-codegen
// (gen function at tools/codegen/src/ffi.rs).
// It is not intended for manual editing.

#![cfg_attr(rustfmt, rustfmt::skip)]

pub const SYS_syscall: u32 = 0;
pub const SYS_exit: u32 = 1;
pub const SYS_fork: u32 = 2;
pub const SYS_read: u32 = 3;
pub const SYS_write: u32 = 4;
pub const SYS_open: u32 = 5;
pub const SYS_close: u32 = 6;
pub const SYS_wait4: u32 = 7;
pub const SYS_link: u32 = 9;
pub const SYS_unlink: u32 = 10;
pub const SYS_chdir: u32 = 12;
pub const SYS_fchdir: u32 = 13;
pub const SYS_freebsd11_mknod: u32 = 14;
pub const SYS_chmod: u32 = 15;
pub const SYS_chown: u32 = 16;
pub const SYS_break: u32 = 17;
pub const SYS_getpid: u32 = 20;
pub const SYS_mount: u32 = 21;
pub const SYS_unmount: u32 = 22;
pub const SYS_setuid: u32 = 23;
pub const SYS_getuid: u32 = 24;
pub const SYS_geteuid: u32 = 25;
pub const SYS_ptrace: u32 = 26;
pub const SYS_recvmsg: u32 = 27;
pub const SYS_sendmsg: u32 = 28;
pub const SYS_recvfrom: u32 = 29;
pub const SYS_accept: u32 = 30;
pub const SYS_getpeername: u32 = 31;
pub const SYS_getsockname: u32 = 32;
pub const SYS_access: u32 = 33;
pub const SYS_chflags: u32 = 34;
pub const SYS_fchflags: u32 = 35;
pub const SYS_sync: u32 = 36;
pub const SYS_kill: u32 = 37;
pub const SYS_getppid: u32 = 39;
pub const SYS_dup: u32 = 41;
pub const SYS_freebsd10_pipe: u32 = 42;
pub const SYS_getegid: u32 = 43;
pub const SYS_profil: u32 = 44;
pub const SYS_ktrace: u32 = 45;
pub const SYS_getgid: u32 = 47;
pub const SYS_getlogin: u32 = 49;
pub const SYS_setlogin: u32 = 50;
pub const SYS_acct: u32 = 51;
pub const SYS_sigaltstack: u32 = 53;
pub const SYS_ioctl: u32 = 54;
pub const SYS_reboot: u32 = 55;
pub const SYS_revoke: u32 = 56;
pub const SYS_symlink: u32 = 57;
pub const SYS_readlink: u32 = 58;
pub const SYS_execve: u32 = 59;
pub const SYS_umask: u32 = 60;
pub const SYS_chroot: u32 = 61;
pub const SYS_msync: u32 = 65;
pub const SYS_vfork: u32 = 66;
pub const SYS_freebsd11_vadvise: u32 = 72;
pub const SYS_munmap: u32 = 73;
pub const SYS_mprotect: u32 = 74;
pub const SYS_madvise: u32 = 75;
pub const SYS_mincore: u32 = 78;
pub const SYS_getgroups: u32 = 79;
pub const SYS_setgroups: u32 = 80;
pub const SYS_getpgrp: u32 = 81;
pub const SYS_setpgid: u32 = 82;
pub const SYS_setitimer: u32 = 83;
pub const SYS_swapon: u32 = 85;
pub const SYS_getitimer: u32 = 86;
pub const SYS_getdtablesize: u32 = 89;
pub const SYS_dup2: u32 = 90;
pub const SYS_fcntl: u32 = 92;
pub const SYS_select: u32 = 93;
pub const SYS_fsync: u32 = 95;
pub const SYS_setpriority: u32 = 96;
pub const SYS_socket: u32 = 97;
pub const SYS_connect: u32 = 98;
pub const SYS_getpriority: u32 = 100;
pub const SYS_bind: u32 = 104;
pub const SYS_setsockopt: u32 = 105;
pub const SYS_listen: u32 = 106;
pub const SYS_gettimeofday: u32 = 116;
pub const SYS_getrusage: u32 = 117;
pub const SYS_getsockopt: u32 = 118;
pub const SYS_readv: u32 = 120;
pub const SYS_writev: u32 = 121;
pub const SYS_settimeofday: u32 = 122;
pub const SYS_fchown: u32 = 123;
pub const SYS_fchmod: u32 = 124;
pub const SYS_setreuid: u32 = 126;
pub const SYS_setregid: u32 = 127;
pub const SYS_rename: u32 = 128;
pub const SYS_flock: u32 = 131;
pub const SYS_mkfifo: u32 = 132;
pub const SYS_sendto: u32 = 133;
pub const SYS_shutdown: u32 = 134;
pub const SYS_socketpair: u32 = 135;
pub const SYS_mkdir: u32 = 136;
pub const SYS_rmdir: u32 = 137;
pub const SYS_utimes: u32 = 138;
pub const SYS_adjtime: u32 = 140;
pub const SYS_setsid: u32 = 147;
pub const SYS_quotactl: u32 = 148;
pub const SYS_nlm_syscall: u32 = 154;
pub const SYS_nfssvc: u32 = 155;
pub const SYS_lgetfh: u32 = 160;
pub const SYS_getfh: u32 = 161;
pub const SYS_sysarch: u32 = 165;
pub const SYS_rtprio: u32 = 166;
pub const SYS_semsys: u32 = 169;
pub const SYS_msgsys: u32 = 170;
pub const SYS_shmsys: u32 = 171;
pub const SYS_setfib: u32 = 175;
pub const SYS_ntp_adjtime: u32 = 176;
pub const SYS_setgid: u32 = 181;
pub const SYS_setegid: u32 = 182;
pub const SYS_seteuid: u32 = 183;
pub const SYS_freebsd11_stat: u32 = 188;
pub const SYS_freebsd11_fstat: u32 = 189;
pub const SYS_freebsd11_lstat: u32 = 190;
pub const SYS_pathconf: u32 = 191;
pub const SYS_fpathconf: u32 = 192;
pub const SYS_getrlimit: u32 = 194;
pub const SYS_setrlimit: u32 = 195;
pub const SYS_freebsd11_getdirentries: u32 = 196;
pub const SYS___syscall: u32 = 198;
pub const SYS___sysctl: u32 = 202;
pub const SYS_mlock: u32 = 203;
pub const SYS_munlock: u32 = 204;
pub const SYS_undelete: u32 = 205;
pub const SYS_futimes: u32 = 206;
pub const SYS_getpgid: u32 = 207;
pub const SYS_poll: u32 = 209;
pub const SYS_freebsd7___semctl: u32 = 220;
pub const SYS_semget: u32 = 221;
pub const SYS_semop: u32 = 222;
pub const SYS_freebsd7_msgctl: u32 = 224;
pub const SYS_msgget: u32 = 225;
pub const SYS_msgsnd: u32 = 226;
pub const SYS_msgrcv: u32 = 227;
pub const SYS_shmat: u32 = 228;
pub const SYS_freebsd7_shmctl: u32 = 229;
pub const SYS_shmdt: u32 = 230;
pub const SYS_shmget: u32 = 231;
pub const SYS_clock_gettime: u32 = 232;
pub const SYS_clock_settime: u32 = 233;
pub const SYS_clock_getres: u32 = 234;
pub const SYS_ktimer_create: u32 = 235;
pub const SYS_ktimer_delete: u32 = 236;
pub const SYS_ktimer_settime: u32 = 237;
pub const SYS_ktimer_gettime: u32 = 238;
pub const SYS_ktimer_getoverrun: u32 = 239;
pub const SYS_nanosleep: u32 = 240;
pub const SYS_ffclock_getcounter: u32 = 241;
pub const SYS_ffclock_setestimate: u32 = 242;
pub const SYS_ffclock_getestimate: u32 = 243;
pub const SYS_clock_nanosleep: u32 = 244;
pub const SYS_clock_getcpuclockid2: u32 = 247;
pub const SYS_ntp_gettime: u32 = 248;
pub const SYS_minherit: u32 = 250;
pub const SYS_rfork: u32 = 251;
pub const SYS_issetugid: u32 = 253;
pub const SYS_lchown: u32 = 254;
pub const SYS_aio_read: u32 = 255;
pub const SYS_aio_write: u32 = 256;
pub const SYS_lio_listio: u32 = 257;
pub const SYS_freebsd11_getdents: u32 = 272;
pub const SYS_lchmod: u32 = 274;
pub const SYS_lutimes: u32 = 276;
pub const SYS_freebsd11_nstat: u32 = 278;
pub const SYS_freebsd11_nfstat: u32 = 279;
pub const SYS_freebsd11_nlstat: u32 = 280;
pub const SYS_preadv: u32 = 289;
pub const SYS_pwritev: u32 = 290;
pub const SYS_fhopen: u32 = 298;
pub const SYS_freebsd11_fhstat: u32 = 299;
pub const SYS_modnext: u32 = 300;
pub const SYS_modstat: u32 = 301;
pub const SYS_modfnext: u32 = 302;
pub const SYS_modfind: u32 = 303;
pub const SYS_kldload: u32 = 304;
pub const SYS_kldunload: u32 = 305;
pub const SYS_kldfind: u32 = 306;
pub const SYS_kldnext: u32 = 307;
pub const SYS_kldstat: u32 = 308;
pub const SYS_kldfirstmod: u32 = 309;
pub const SYS_getsid: u32 = 310;
pub const SYS_setresuid: u32 = 311;
pub const SYS_setresgid: u32 = 312;
pub const SYS_aio_return: u32 = 314;
pub const SYS_aio_suspend: u32 = 315;
pub const SYS_aio_cancel: u32 = 316;
pub const SYS_aio_error: u32 = 317;
pub const SYS_yield: u32 = 321;
pub const SYS_mlockall: u32 = 324;
pub const SYS_munlockall: u32 = 325;
pub const SYS___getcwd: u32 = 326;
pub const SYS_sched_setparam: u32 = 327;
pub const SYS_sched_getparam: u32 = 328;
pub const SYS_sched_setscheduler: u32 = 329;
pub const SYS_sched_getscheduler: u32 = 330;
pub const SYS_sched_yield: u32 = 331;
pub const SYS_sched_get_priority_max: u32 = 332;
pub const SYS_sched_get_priority_min: u32 = 333;
pub const SYS_sched_rr_get_interval: u32 = 334;
pub const SYS_utrace: u32 = 335;
pub const SYS_kldsym: u32 = 337;
pub const SYS_jail: u32 = 338;
pub const SYS_nnpfs_syscall: u32 = 339;
pub const SYS_sigprocmask: u32 = 340;
pub const SYS_sigsuspend: u32 = 341;
pub const SYS_sigpending: u32 = 343;
pub const SYS_sigtimedwait: u32 = 345;
pub const SYS_sigwaitinfo: u32 = 346;
pub const SYS___acl_get_file: u32 = 347;
pub const SYS___acl_set_file: u32 = 348;
pub const SYS___acl_get_fd: u32 = 349;
pub const SYS___acl_set_fd: u32 = 350;
pub const SYS___acl_delete_file: u32 = 351;
pub const SYS___acl_delete_fd: u32 = 352;
pub const SYS___acl_aclcheck_file: u32 = 353;
pub const SYS___acl_aclcheck_fd: u32 = 354;
pub const SYS_extattrctl: u32 = 355;
pub const SYS_extattr_set_file: u32 = 356;
pub const SYS_extattr_get_file: u32 = 357;
pub const SYS_extattr_delete_file: u32 = 358;
pub const SYS_aio_waitcomplete: u32 = 359;
pub const SYS_getresuid: u32 = 360;
pub const SYS_getresgid: u32 = 361;
pub const SYS_kqueue: u32 = 362;
pub const SYS_freebsd11_kevent: u32 = 363;
pub const SYS_extattr_set_fd: u32 = 371;
pub const SYS_extattr_get_fd: u32 = 372;
pub const SYS_extattr_delete_fd: u32 = 373;
pub const SYS___setugid: u32 = 374;
pub const SYS_eaccess: u32 = 376;
pub const SYS_afs3_syscall: u32 = 377;
pub const SYS_nmount: u32 = 378;
pub const SYS___mac_get_proc: u32 = 384;
pub const SYS___mac_set_proc: u32 = 385;
pub const SYS___mac_get_fd: u32 = 386;
pub const SYS___mac_get_file: u32 = 387;
pub const SYS___mac_set_fd: u32 = 388;
pub const SYS___mac_set_file: u32 = 389;
pub const SYS_kenv: u32 = 390;
pub const SYS_lchflags: u32 = 391;
pub const SYS_uuidgen: u32 = 392;
pub const SYS_sendfile: u32 = 393;
pub const SYS_mac_syscall: u32 = 394;
pub const SYS_freebsd11_getfsstat: u32 = 395;
pub const SYS_freebsd11_statfs: u32 = 396;
pub const SYS_freebsd11_fstatfs: u32 = 397;
pub const SYS_freebsd11_fhstatfs: u32 = 398;
pub const SYS_ksem_close: u32 = 400;
pub const SYS_ksem_post: u32 = 401;
pub const SYS_ksem_wait: u32 = 402;
pub const SYS_ksem_trywait: u32 = 403;
pub const SYS_ksem_init: u32 = 404;
pub const SYS_ksem_open: u32 = 405;
pub const SYS_ksem_unlink: u32 = 406;
pub const SYS_ksem_getvalue: u32 = 407;
pub const SYS_ksem_destroy: u32 = 408;
pub const SYS___mac_get_pid: u32 = 409;
pub const SYS___mac_get_link: u32 = 410;
pub const SYS___mac_set_link: u32 = 411;
pub const SYS_extattr_set_link: u32 = 412;
pub const SYS_extattr_get_link: u32 = 413;
pub const SYS_extattr_delete_link: u32 = 414;
pub const SYS___mac_execve: u32 = 415;
pub const SYS_sigaction: u32 = 416;
pub const SYS_sigreturn: u32 = 417;
pub const SYS_getcontext: u32 = 421;
pub const SYS_setcontext: u32 = 422;
pub const SYS_swapcontext: u32 = 423;
pub const SYS_freebsd13_swapoff: u32 = 424;
pub const SYS___acl_get_link: u32 = 425;
pub const SYS___acl_set_link: u32 = 426;
pub const SYS___acl_delete_link: u32 = 427;
pub const SYS___acl_aclcheck_link: u32 = 428;
pub const SYS_sigwait: u32 = 429;
pub const SYS_thr_create: u32 = 430;
pub const SYS_thr_exit: u32 = 431;
pub const SYS_thr_self: u32 = 432;
pub const SYS_thr_kill: u32 = 433;
pub const SYS_freebsd10__umtx_lock: u32 = 434;
pub const SYS_freebsd10__umtx_unlock: u32 = 435;
pub const SYS_jail_attach: u32 = 436;
pub const SYS_extattr_list_fd: u32 = 437;
pub const SYS_extattr_list_file: u32 = 438;
pub const SYS_extattr_list_link: u32 = 439;
pub const SYS_ksem_timedwait: u32 = 441;
pub const SYS_thr_suspend: u32 = 442;
pub const SYS_thr_wake: u32 = 443;
pub const SYS_kldunloadf: u32 = 444;
pub const SYS_audit: u32 = 445;
pub const SYS_auditon: u32 = 446;
pub const SYS_getauid: u32 = 447;
pub const SYS_setauid: u32 = 448;
pub const SYS_getaudit: u32 = 449;
pub const SYS_setaudit: u32 = 450;
pub const SYS_getaudit_addr: u32 = 451;
pub const SYS_setaudit_addr: u32 = 452;
pub const SYS_auditctl: u32 = 453;
pub const SYS__umtx_op: u32 = 454;
pub const SYS_thr_new: u32 = 455;
pub const SYS_sigqueue: u32 = 456;
pub const SYS_kmq_open: u32 = 457;
pub const SYS_kmq_setattr: u32 = 458;
pub const SYS_kmq_timedreceive: u32 = 459;
pub const SYS_kmq_timedsend: u32 = 460;
pub const SYS_kmq_notify: u32 = 461;
pub const SYS_kmq_unlink: u32 = 462;
pub const SYS_abort2: u32 = 463;
pub const SYS_thr_set_name: u32 = 464;
pub const SYS_aio_fsync: u32 = 465;
pub const SYS_rtprio_thread: u32 = 466;
pub const SYS_sctp_peeloff: u32 = 471;
pub const SYS_sctp_generic_sendmsg: u32 = 472;
pub const SYS_sctp_generic_sendmsg_iov: u32 = 473;
pub const SYS_sctp_generic_recvmsg: u32 = 474;
pub const SYS_pread: u32 = 475;
pub const SYS_pwrite: u32 = 476;
pub const SYS_mmap: u32 = 477;
pub const SYS_lseek: u32 = 478;
pub const SYS_truncate: u32 = 479;
pub const SYS_ftruncate: u32 = 480;
pub const SYS_thr_kill2: u32 = 481;
pub const SYS_freebsd12_shm_open: u32 = 482;
pub const SYS_shm_unlink: u32 = 483;
pub const SYS_cpuset: u32 = 484;
pub const SYS_cpuset_setid: u32 = 485;
pub const SYS_cpuset_getid: u32 = 486;
pub const SYS_cpuset_getaffinity: u32 = 487;
pub const SYS_cpuset_setaffinity: u32 = 488;
pub const SYS_faccessat: u32 = 489;
pub const SYS_fchmodat: u32 = 490;
pub const SYS_fchownat: u32 = 491;
pub const SYS_fexecve: u32 = 492;
pub const SYS_freebsd11_fstatat: u32 = 493;
pub const SYS_futimesat: u32 = 494;
pub const SYS_linkat: u32 = 495;
pub const SYS_mkdirat: u32 = 496;
pub const SYS_mkfifoat: u32 = 497;
pub const SYS_freebsd11_mknodat: u32 = 498;
pub const SYS_openat: u32 = 499;
pub const SYS_readlinkat: u32 = 500;
pub const SYS_renameat: u32 = 501;
pub const SYS_symlinkat: u32 = 502;
pub const SYS_unlinkat: u32 = 503;
pub const SYS_posix_openpt: u32 = 504;
pub const SYS_gssd_syscall: u32 = 505;
pub const SYS_jail_get: u32 = 506;
pub const SYS_jail_set: u32 = 507;
pub const SYS_jail_remove: u32 = 508;
pub const SYS_freebsd12_closefrom: u32 = 509;
pub const SYS___semctl: u32 = 510;
pub const SYS_msgctl: u32 = 511;
pub const SYS_shmctl: u32 = 512;
pub const SYS_lpathconf: u32 = 513;
pub const SYS___cap_rights_get: u32 = 515;
pub const SYS_cap_enter: u32 = 516;
pub const SYS_cap_getmode: u32 = 517;
pub const SYS_pdfork: u32 = 518;
pub const SYS_pdkill: u32 = 519;
pub const SYS_pdgetpid: u32 = 520;
pub const SYS_pselect: u32 = 522;
pub const SYS_getloginclass: u32 = 523;
pub const SYS_setloginclass: u32 = 524;
pub const SYS_rctl_get_racct: u32 = 525;
pub const SYS_rctl_get_rules: u32 = 526;
pub const SYS_rctl_get_limits: u32 = 527;
pub const SYS_rctl_add_rule: u32 = 528;
pub const SYS_rctl_remove_rule: u32 = 529;
pub const SYS_posix_fallocate: u32 = 530;
pub const SYS_posix_fadvise: u32 = 531;
pub const SYS_wait6: u32 = 532;
pub const SYS_cap_rights_limit: u32 = 533;
pub const SYS_cap_ioctls_limit: u32 = 534;
pub const SYS_cap_ioctls_get: u32 = 535;
pub const SYS_cap_fcntls_limit: u32 = 536;
pub const SYS_cap_fcntls_get: u32 = 537;
pub const SYS_bindat: u32 = 538;
pub const SYS_connectat: u32 = 539;
pub const SYS_chflagsat: u32 = 540;
pub const SYS_accept4: u32 = 541;
pub const SYS_pipe2: u32 = 542;
pub const SYS_aio_mlock: u32 = 543;
pub const SYS_procctl: u32 = 544;
pub const SYS_ppoll: u32 = 545;
pub const SYS_futimens: u32 = 546;
pub const SYS_utimensat: u32 = 547;
pub const SYS_fdatasync: u32 = 550;
pub const SYS_fstat: u32 = 551;
pub const SYS_fstatat: u32 = 552;
pub const SYS_fhstat: u32 = 553;
pub const SYS_getdirentries: u32 = 554;
pub const SYS_statfs: u32 = 555;
pub const SYS_fstatfs: u32 = 556;
pub const SYS_getfsstat: u32 = 557;
pub const SYS_fhstatfs: u32 = 558;
pub const SYS_mknodat: u32 = 559;
pub const SYS_kevent: u32 = 560;
pub const SYS_cpuset_getdomain: u32 = 561;
pub const SYS_cpuset_setdomain: u32 = 562;
pub const SYS_getrandom: u32 = 563;
pub const SYS_getfhat: u32 = 564;
pub const SYS_fhlink: u32 = 565;
pub const SYS_fhlinkat: u32 = 566;
pub const SYS_fhreadlink: u32 = 567;
pub const SYS_funlinkat: u32 = 568;
pub const SYS_copy_file_range: u32 = 569;
pub const SYS___sysctlbyname: u32 = 570;
pub const SYS_shm_open2: u32 = 571;
pub const SYS_shm_rename: u32 = 572;
pub const SYS_sigfastblock: u32 = 573;
pub const SYS___realpathat: u32 = 574;
pub const SYS_close_range: u32 = 575;
pub const SYS_rpctls_syscall: u32 = 576;
pub const SYS___specialfd: u32 = 577;
pub const SYS_aio_writev: u32 = 578;
pub const SYS_aio_readv: u32 = 579;
pub const SYS_fspacectl: u32 = 580;
pub const SYS_sched_getcpu: u32 = 581;
pub const SYS_swapoff: u32 = 582;
pub const SYS_kqueuex: u32 = 583;
pub const SYS_membarrier: u32 = 584;
pub const SYS_timerfd_create: u32 = 585;
pub const SYS_timerfd_gettime: u32 = 586;
pub const SYS_timerfd_settime: u32 = 587;
pub const SYS_kcmp: u32 = 588;
pub const SYS_getrlimitusage: u32 = 589;
pub const SYS_MAXSYSCALL: u32 = 590;

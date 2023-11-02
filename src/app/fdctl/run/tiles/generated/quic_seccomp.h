/* THIS FILE WAS GENERATED BY generate_filters.py. DO NOT EDIT BY HAND! */
#ifndef HEADER_fd_src_app_fdctl_run_tiles_generated_quic_seccomp_h
#define HEADER_fd_src_app_fdctl_run_tiles_generated_quic_seccomp_h

#include "../../../../../../src/util/fd_util_base.h"
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <signal.h>
#include <stddef.h>

#if defined(__i386__)
# define ARCH_NR  AUDIT_ARCH_I386
#elif defined(__x86_64__)
# define ARCH_NR  AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
# define ARCH_NR AUDIT_ARCH_AARCH64
#else
# error "Target architecture is unsupported by seccomp."
#endif
static const unsigned int sock_filter_policy_quic_instr_cnt = 34;

static void populate_sock_filter_policy_quic( ulong out_cnt, struct sock_filter * out, unsigned int logfile_fd, unsigned int netlink_fd) {
  FD_TEST( out_cnt >= 34 );
  struct sock_filter filter[34] = {
    /* Check: Jump to RET_KILL_PROCESS if the script's arch != the runtime arch */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, ( offsetof( struct seccomp_data, arch ) ) ),
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, ARCH_NR, 0, /* RET_KILL_PROCESS */ 30 ),
    /* loading syscall number in accumulator */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, ( offsetof( struct seccomp_data, nr ) ) ),
    /* allow write based on expression */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, __NR_write, /* check_write */ 6, 0 ),
    /* allow fsync based on expression */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, __NR_fsync, /* check_fsync */ 9, 0 ),
    /* simply allow getpid */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, __NR_getpid, /* RET_ALLOW */ 27, 0 ),
    /* simply allow getrandom */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, __NR_getrandom, /* RET_ALLOW */ 26, 0 ),
    /* allow sendto based on expression */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, __NR_sendto, /* check_sendto */ 8, 0 ),
    /* allow recvfrom based on expression */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, __NR_recvfrom, /* check_recvfrom */ 15, 0 ),
    /* none of the syscalls matched */
    { BPF_JMP | BPF_JA, 0, 0, /* RET_KILL_PROCESS */ 22 },
//  check_write:
    /* load syscall argument 0 in accumulator */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, 2, /* RET_ALLOW */ 21, /* lbl_1 */ 0 ),
//  lbl_1:
    /* load syscall argument 0 in accumulator */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, logfile_fd, /* RET_ALLOW */ 19, /* RET_KILL_PROCESS */ 18 ),
//  check_fsync:
    /* load syscall argument 0 in accumulator */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, logfile_fd, /* RET_ALLOW */ 17, /* RET_KILL_PROCESS */ 16 ),
//  check_sendto:
    /* load syscall argument 0 in accumulator */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, netlink_fd, /* lbl_2 */ 0, /* RET_KILL_PROCESS */ 14 ),
//  lbl_2:
    /* load syscall argument 3 in accumulator */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[3])),
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, 0, /* lbl_3 */ 0, /* RET_KILL_PROCESS */ 12 ),
//  lbl_3:
    /* load syscall argument 4 in accumulator */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[4])),
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, 0, /* lbl_4 */ 0, /* RET_KILL_PROCESS */ 10 ),
//  lbl_4:
    /* load syscall argument 5 in accumulator */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[5])),
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, 0, /* RET_ALLOW */ 9, /* RET_KILL_PROCESS */ 8 ),
//  check_recvfrom:
    /* load syscall argument 0 in accumulator */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, netlink_fd, /* lbl_5 */ 0, /* RET_KILL_PROCESS */ 6 ),
//  lbl_5:
    /* load syscall argument 3 in accumulator */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[3])),
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, 0, /* lbl_6 */ 0, /* RET_KILL_PROCESS */ 4 ),
//  lbl_6:
    /* load syscall argument 4 in accumulator */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[4])),
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, 0, /* lbl_7 */ 0, /* RET_KILL_PROCESS */ 2 ),
//  lbl_7:
    /* load syscall argument 5 in accumulator */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[5])),
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, 0, /* RET_ALLOW */ 1, /* RET_KILL_PROCESS */ 0 ),
//  RET_KILL_PROCESS:
    /* KILL_PROCESS is placed before ALLOW since it's the fallthrough case. */
    BPF_STMT( BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS ),
//  RET_ALLOW:
    /* ALLOW has to be reached by jumping */
    BPF_STMT( BPF_RET | BPF_K, SECCOMP_RET_ALLOW ),
  };
  fd_memcpy( out, filter, sizeof( filter ) );
}

#endif

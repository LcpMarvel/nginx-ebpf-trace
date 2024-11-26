#ifndef __NGINX_TRACE_H
#define __NGINX_TRACE_H

#ifdef __BPF__
#include "vmlinux.h"
#else
#include <linux/types.h>
#endif

struct event {
    bool is_ipv4;
    bool is_internet_0;
    bool is_internet_1;
    __u32 ip_src;
    __u32 ip_dst;
    char protocol[8];
    __u16 client_port;
    __u16 server_port;
    __u32 req_tcp_seq;
    __u32 resp_tcp_seq;
    char l7_protocol[8];
    char raw_http[2048];
    int status_code;
    __u32 pid;
    __u64 timestamp;
} __attribute__((packed));

#endif /* __NGINX_TRACE_H */

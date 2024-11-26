#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "nginx_trace.h"

#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

#ifndef __section_tail
# define __section_tail(ID, KEY)          \
   __section(__stringify(ID) "/" __stringify(KEY))
#endif

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct event));
    __uint(max_entries, 1);
} heap SEC(".maps");

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_TCP 6
#define NGINX_PORT 80
#define NGINX_PORT_SSL 443

static __always_inline void process_http(struct xdp_md *ctx,
                                       const void *data_end,
                                       const void *data,
                                       const struct iphdr *iph,
                                       const struct tcphdr *tcph) {
    // 获取 per-cpu 数组中的事件结构体
    __u32 zero = 0;
    struct event *event = bpf_map_lookup_elem(&heap, &zero);
    if (!event)
        return;

    // 计算HTTP负载的起始位置
    const unsigned char *payload_start = (const unsigned char *)tcph + (tcph->doff * 4);
    if (payload_start + 1 > (const unsigned char *)data_end)
        return;

    // 初始化事件结构体 - 手动初始化关键字段
    event->timestamp = 0;
    event->is_ipv4 = 0;
    event->client_port = 0;
    event->server_port = 0;
    event->req_tcp_seq = 0;
    event->resp_tcp_seq = 0;
    event->status_code = 0;
    event->pid = 0;
    event->ip_src = 0;
    event->ip_dst = 0;

    // 清空字符串字段
    event->protocol[0] = '\0';
    event->l7_protocol[0] = '\0';
    event->raw_http[0] = '\0';

    // 设置基本信息
    event->timestamp = bpf_ktime_get_ns();
    event->is_ipv4 = true;

    // 直接存储原始IP地址
    event->ip_src = iph->saddr;
    event->ip_dst = iph->daddr;

    // 设置协议信息
    event->protocol[0] = 'T';
    event->protocol[1] = 'C';
    event->protocol[2] = 'P';
    event->protocol[3] = '\0';

    event->l7_protocol[0] = 'H';
    event->l7_protocol[1] = 'T';
    event->l7_protocol[2] = 'T';
    event->l7_protocol[3] = 'P';
    event->l7_protocol[4] = '\0';

    // 设置端口信息
    event->client_port = bpf_ntohs(tcph->source);
    event->server_port = bpf_ntohs(tcph->dest);
    event->req_tcp_seq = bpf_ntohl(tcph->seq);

    // 计算可以安全拷贝的HTTP内容长度
    long available_len = (const unsigned char *)data_end - payload_start;
    if (available_len <= 0)
        return;

    long copy_len = available_len;
    if (copy_len > sizeof(event->raw_http) - 1)
        copy_len = sizeof(event->raw_http) - 1;

    // 拷贝HTTP内容
    int ret = bpf_probe_read_kernel(event->raw_http, copy_len, payload_start);
    if (ret < 0)
        return;

    event->raw_http[copy_len] = '\0';

    // 检查是否是HTTP请求（简单检查）
    if (copy_len >= 4) {
        char first_bytes[4];
        ret = bpf_probe_read_kernel(first_bytes, 4, payload_start);
        if (ret == 0) {
            // 检查是否以常见的HTTP方法开头
            if (first_bytes[0] == 'G' || // GET
                first_bytes[0] == 'P' || // POST, PUT
                first_bytes[0] == 'H' || // HEAD
                first_bytes[0] == 'D' || // DELETE
                first_bytes[0] == 'O' || // OPTIONS
                first_bytes[0] == 'T' || // TRACE
                first_bytes[0] == 'C') { // CONNECT
                // 发送事件
                bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
            }
        }
    }
}

SEC("xdp/nginx_trace")
int nginx_trace(struct xdp_md *ctx) {
    const void *data_end = (void *)(long)ctx->data_end;
    const void *data = (void *)(long)ctx->data;

    const struct ethhdr *eth = data;
    if ((const void *)(eth + 1) > data_end) {
        bpf_printk("Invalid eth header\n");

        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        bpf_printk("Not IP packet: proto=%x\n", bpf_ntohs(eth->h_proto));

        return XDP_PASS;
    }

    const struct iphdr *iph = (const struct iphdr *)(eth + 1);
    if ((const void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    if (iph->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    const struct tcphdr *tcph = (const struct tcphdr *)(iph + 1);
    if ((const void *)(tcph + 1) > data_end) {
        return XDP_PASS;
    }

    // 检查目标端口是否是Nginx端口
    __u16 dport = bpf_ntohs(tcph->dest);
    if (dport != NGINX_PORT && dport != NGINX_PORT_SSL) {
        return XDP_PASS;
    }

    process_http(ctx, data_end, data, iph, tcph);

    return XDP_PASS;
}


char LICENSE[] SEC("license") = "GPL";

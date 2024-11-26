#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include "nginx_trace.h"
#include "nginx_trace.skel.h"
#include <bpf/bpf.h>
#include <arpa/inet.h>

static volatile bool exiting = false;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static void sig_handler(int sig) {
    exiting = true;
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_size) {
    const struct event *e = data;
    printf("New HTTP Request:\n");

    char src_ip[16];
    char dst_ip[16];
    struct in_addr src_addr = { .s_addr = e->ip_src };
    struct in_addr dst_addr = { .s_addr = e->ip_dst };

    inet_ntop(AF_INET, &src_addr, src_ip, 16);
    inet_ntop(AF_INET, &dst_addr, dst_ip, 16);

    printf("Source IP: %s\n", src_ip);
    printf("Dest IP: %s\n", dst_ip);

    printf("Protocol: %s\n", e->protocol);
    printf("Client Port: %d\n", e->client_port);
    printf("Server Port: %d\n", e->server_port);
    printf("Raw Info: \n 这里是http的文本信息 ====================\n%s\n =====================\n", e->raw_http);
    printf("Timestamp: %llu\n\n", e->timestamp);
}

int main(int argc, char **argv) {
    struct nginx_trace_bpf *skel;
    struct perf_buffer *pb = NULL;
    int err;

    // 设置 libbpf 调试输出
    libbpf_set_print(libbpf_print_fn);

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
        return 1;
    }

    // 获取接口索引
    int ifindex = if_nametoindex(argv[1]);
    if (ifindex == 0) {
        fprintf(stderr, "Failed to get interface index for %s: %s\n",
                argv[1], strerror(errno));
        return 1;
    }

    // 设置信号处理
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 打开 BPF 程序
    skel = nginx_trace_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // 加载 BPF 程序
    err = nginx_trace_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    // 附加 XDP 程序
    int prog_fd = bpf_program__fd(skel->progs.nginx_trace);

    // 先尝试卸载可能存在的 XDP 程序
    err = bpf_set_link_xdp_fd(ifindex, -1, 0);
    if (err) {
        fprintf(stderr, "Failed to remove existing XDP program: %s\n", strerror(-err));
    }

    // 尝试用 generic 模式附加
    err = bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_SKB_MODE);
    if (err) {
        fprintf(stderr, "Failed to attach XDP program to interface %s (generic mode): %s\n",
                argv[1], strerror(-err));

        // 如果失败，尝试 native 模式
        err = bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_DRV_MODE);
        if (err) {
            fprintf(stderr, "Failed to attach XDP program to interface %s (native mode): %s\n",
                    argv[1], strerror(-err));
            goto cleanup;
        }
    }

    printf("Successfully attached XDP program to interface %s\n", argv[1]);

    // 设置 perf buffer
    struct perf_buffer_opts pb_opts = {};
    pb_opts.sample_cb = handle_event;
    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 8, &pb_opts);
    if (!pb) {
        err = -1;
        fprintf(stderr, "Failed to create perf buffer\n");
        goto cleanup;
    }

    printf("Successfully started! Please run (sudo cat /sys/kernel/debug/tracing/trace_pipe) "
           "to see output\n");

    // 主循环
    while (!exiting) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            goto cleanup;
        }
    }

cleanup:
    // 在清理时确保解除 XDP 程序
    if (ifindex) {
        bpf_set_link_xdp_fd(ifindex, -1, 0);
    }
    perf_buffer__free(pb);
    nginx_trace_bpf__destroy(skel);
    return err != 0;
}

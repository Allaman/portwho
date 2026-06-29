/*
 * portwho — List all open ports and their associated processes.
 *
 * Pure C, no external libraries. Cross-platform:
 *   Linux  → reads /proc/net/tcp*, /proc/net/udp*, resolves inodes via /proc
 *   macOS  → sysctl(NET_RT_DUMP2) + libproc.h (no external tools)
 *
 * Usage:  ./portwho [--tcp|--udp|--all] [--listening|--established|--all-states]
 *
 * Compile:  gcc -O2 -o portwho portwho.c
 *   (Linux may need root for full visibility into other users' processes.)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <sys/ioctl.h>

#if defined(__linux__)
#  include <dirent.h>
#  include <unistd.h>
#  include <sys/stat.h>
#elif defined(__APPLE__)
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <sys/sysctl.h>
#  include <netinet/in.h>
#  include <libproc.h>
#  include <arpa/inet.h>
#  include <errno.h>
#  include <unistd.h>
#else
#  error "Unsupported platform"
#endif

/* ------------------------------------------------------------------ */
/*  Configuration                                                     */
/* ------------------------------------------------------------------ */

#define MAX_ENTRIES  8192
#define PATH_BUF     256
#define NAME_BUF     512
#define LINE_BUF     2048

/* ------------------------------------------------------------------ */
/*  Data structures (shared)                                          */
/* ------------------------------------------------------------------ */

typedef enum { PROTO_TCP, PROTO_UDP } Proto;

typedef struct {
    Proto    proto;
    char     local_addr[64];
    int      local_port;
    char     remote_addr[64];
    int      remote_port;
    char     state[24];
    unsigned inode;      /* Linux only */
    int      pid;
    char     process[NAME_BUF];
} SocketEntry;

/* ------------------------------------------------------------------ */
/*  CLI filters (shared)                                              */
/* ------------------------------------------------------------------ */

typedef enum { FILTER_ALL, FILTER_TCP, FILTER_UDP } ProtoFilter;
typedef enum { STATE_ALL, STATE_LISTEN, STATE_ESTABLISHED } StateFilter;
typedef enum { OUTPUT_TABLE, OUTPUT_COMPACT } OutputMode;

static int matches_proto(Proto p, ProtoFilter f)
{
    switch (f) {
        case FILTER_ALL:        return 1;
        case FILTER_TCP:        return p == PROTO_TCP;
        case FILTER_UDP:        return p == PROTO_UDP;
    }
    return 1;
}

static int matches_state(const char *s, StateFilter f)
{
    switch (f) {
        case STATE_ALL:         return 1;
        case STATE_LISTEN:
            return strcmp(s, "LISTEN") == 0 || strcmp(s, "BOUND") == 0;
        case STATE_ESTABLISHED:
            return strcmp(s, "ESTABLISHED") == 0;
    }
    return 1;
}

static void append_text(char *dst, size_t dstsz, const char *src)
{
    size_t used = strlen(dst);
    if (used + 1 >= dstsz) return;
    strncat(dst, src, dstsz - used - 1);
}

/* ------------------------------------------------------------------ */
/*  Output (shared)                                                   */
/* ------------------------------------------------------------------ */

static int terminal_width(void)
{
    struct winsize ws;
    if (isatty(STDOUT_FILENO) &&
        ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 &&
        ws.ws_col > 0) {
        return ws.ws_col;
    }

    const char *cols = getenv("COLUMNS");
    if (cols && atoi(cols) > 0)
        return atoi(cols);

    return 120;
}

static OutputMode output_mode_for_width(int width)
{
    return width < 120 ? OUTPUT_COMPACT : OUTPUT_TABLE;
}

static void print_width_limited(const char *line, int width)
{
    size_t len = strlen(line);
    if (width > 4 && len > (size_t)width) {
        fwrite(line, 1, (size_t)width - 3, stdout);
        fputs("...\n", stdout);
    } else {
        fputs(line, stdout);
        fputc('\n', stdout);
    }
}

static void format_endpoint(char *buf, size_t sz, const char *addr, int port)
{
    if (port <= 0) {
        snprintf(buf, sz, "%s", addr && addr[0] ? addr : "*");
    } else if (addr && strchr(addr, ':')) {
        snprintf(buf, sz, "[%s]:%d", addr, port);
    } else {
        snprintf(buf, sz, "%s:%d", addr && addr[0] ? addr : "*", port);
    }
}

static void print_header(OutputMode mode, int width)
{
    if (mode == OUTPUT_COMPACT) {
        print_width_limited("Proto  Local -> Remote  State  PID Process", width);
        print_width_limited("-----  ----------------  -----  -----------", width);
        return;
    }

    printf("%-6s %-42s %-6s %-42s %-6s %-14s %7s  %s\n",
           "Proto", "Local Address", "Port", "Remote Address", "Port",
           "State", "PID", "Process");
    printf("%-6s %-42s %-6s %-42s %-6s %-14s %7s  %s\n",
           "-----", "------------------------------------------", "-----",
           "------------------------------------------", "-----",
           "------------", "------", "------------------------------------------");
}

static void print_entry(const SocketEntry *e, OutputMode mode, int width)
{
    char proto[4];
    snprintf(proto, sizeof(proto), "%s", e->proto == PROTO_TCP ? "tcp" : "udp");

    char pid_s[16];
    snprintf(pid_s, sizeof(pid_s), e->pid > 0 ? "%d" : "?????",
             e->pid > 0 ? e->pid : 0);

    if (mode == OUTPUT_COMPACT) {
        char local[96], remote[96], line[LINE_BUF];
        format_endpoint(local, sizeof(local), e->local_addr, e->local_port);
        format_endpoint(remote, sizeof(remote), e->remote_addr, e->remote_port);
        snprintf(line, sizeof(line), "%s  %s -> %s  %-12s %s %s",
                 proto, local, remote, e->state, pid_s, e->process);
        print_width_limited(line, width);
        return;
    }

    printf("%-6s %-42s %-6d %-42s %-6d %-14s %7s  %s\n",
           proto, e->local_addr, e->local_port,
           e->remote_addr, e->remote_port,
           e->state, pid_s, e->process);
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "\n"
        "List all open ports and their associated processes.\n"
        "\n"
        "Options:\n"
        "  --tcp              Show only TCP sockets\n"
        "  --udp              Show only UDP sockets\n"
        "  --all              Show both TCP and UDP sockets (default)\n"
        "  --listening        Show TCP LISTEN sockets and bound UDP sockets\n"
        "  --established      Show only ESTABLISHED TCP sockets\n"
        "  --all-states       Show all socket states (default)\n"
        "  --help             Show this help\n"
        "\n"
        "Examples:\n"
        "  %s                  # TCP + UDP, all states\n"
        "  %s --tcp            # TCP only\n"
        "  %s --udp            # UDP only\n"
        "  %s --tcp --established\n",
        prog, prog, prog, prog, prog);
}

/* ================================================================== */
/*  LINUX BACKEND  (procfs)                                           */
/* ================================================================== */

#if defined(__linux__)

/* ------------------------------------------------------------------ */
/*  Hex helpers                                                       */
/* ------------------------------------------------------------------ */

static int xdigit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

static unsigned char hex_byte(const char *s)
{
    return (unsigned char)((xdigit(s[0]) << 4) | xdigit(s[1]));
}

/* ------------------------------------------------------------------ */
/*  Address decoders                                                  */
/* ------------------------------------------------------------------ */

static void decode_ipv4(const char *hex, char *out)
{
    unsigned char b[4];
    for (int i = 0; i < 4; i++)
        b[i] = hex_byte(hex + i * 2);
    snprintf(out, 64, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

/*
 * Decode 32-hex-char IPv6 address from /proc/net/tcp6.
 * Collapses IPv4-mapped (::ffff:x.x.x.x) to dotted-quad.
 */
static void decode_addr_v6(const char *hex, char *out)
{
    unsigned char b[16];
    for (int i = 0; i < 16; i++)
        b[i] = hex_byte(hex + i * 2);

    if (b[0]==0 && b[1]==0 && b[2]==0 && b[3]==0 &&
        b[4]==0 && b[5]==0 && b[6]==0 && b[7]==0 &&
        b[8]==0 && b[9]==0 && b[10]==0xff && b[11]==0xff) {
        snprintf(out, 64, "%u.%u.%u.%u", b[12], b[13], b[14], b[15]);
        return;
    }

    snprintf(out, 64,
        "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
        "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
        b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],
        b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
}

static int decode_port(const char *h)
{
    return (int)(((xdigit(h[0])<<4)|xdigit(h[1]))<<8 |
                  (xdigit(h[2])<<4)|xdigit(h[3]));
}

/* ------------------------------------------------------------------ */
/*  State name                                                        */
/* ------------------------------------------------------------------ */

static const char *state_name(const char *hex)
{
    unsigned int v;
    sscanf(hex, "%x", &v);
    switch (v) {
        case 0x01: return "ESTABLISHED";
        case 0x02: return "SYN_SENT";
        case 0x03: return "SYN_RECV";
        case 0x04: return "FIN_WAIT1";
        case 0x05: return "FIN_WAIT2";
        case 0x06: return "TIME_WAIT";
        case 0x07: return "CLOSE";
        case 0x08: return "CLOSE_WAIT";
        case 0x09: return "LAST_ACK";
        case 0x0A: return "LISTEN";
        case 0x0B: return "CLOSING";
        default:   return "UNKNOWN";
    }
}

/* ------------------------------------------------------------------ */
/*  Parse /proc/net/{tcp,udp}[6]                                      */
/* ------------------------------------------------------------------ */

static int parse_proc_net(const char *path, Proto proto,
                          SocketEntry *entries, int cap)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    char line[LINE_BUF];
    int count = 0;

    if (!fgets(line, sizeof(line), f)) { fclose(f); return 0; }

    int is_v6 = (strstr(path, "tcp6") || strstr(path, "udp6")) ? 1 : 0;

    while (fgets(line, sizeof(line), f) && count < cap) {
        char la[64], ra[64], st[4];
        unsigned inode;
        int lp, rp;

        int matched = sscanf(line,
            "%*d: %63[^:]:%4x %63[^:]:%4x %3s %*s %*s %*u %*u %*u %*u %*u %u",
            la, &lp, ra, &rp, st, &inode);

        if (matched < 6) continue;

        entries[count].proto = proto;
        entries[count].local_port  = lp;
        entries[count].remote_port = rp;
        if (proto == PROTO_UDP)
            strncpy(entries[count].state, "BOUND",
                    sizeof(entries[count].state) - 1);
        else
            strncpy(entries[count].state, state_name(st),
                    sizeof(entries[count].state) - 1);
        entries[count].inode = inode;
        entries[count].pid = -1;
        entries[count].process[0] = '\0';

        if (is_v6) {
            decode_addr_v6(la, entries[count].local_addr);
            decode_addr_v6(ra, entries[count].remote_addr);
        } else {
            decode_ipv4(la, entries[count].local_addr);
            decode_ipv4(ra, entries[count].remote_addr);
        }

        count++;
    }

    fclose(f);
    return count;
}

/* ------------------------------------------------------------------ */
/*  inode → PID  (walk /proc/[pid]/fd/)                              */
/* ------------------------------------------------------------------ */

static int find_pid_by_inode(unsigned inode)
{
    DIR *proc = opendir("/proc");
    if (!proc) return -1;

    struct dirent *de;
    while ((de = readdir(proc)) != NULL) {
        if (!isdigit((unsigned char)de->d_name[0])) continue;

        char fd_path[PATH_BUF];
        snprintf(fd_path, PATH_BUF, "/proc/%s/fd", de->d_name);

        DIR *fd_dir = opendir(fd_path);
        if (!fd_dir) continue;

        struct dirent *fd_de;
        while ((fd_de = readdir(fd_dir)) != NULL) {
            if (!isdigit((unsigned char)fd_de->d_name[0])) continue;

            char link[PATH_BUF], target[PATH_BUF];
            snprintf(link, PATH_BUF, "/proc/%s/fd/%s",
                     de->d_name, fd_de->d_name);

            if (readlink(link, target, PATH_BUF - 1) <= 0) continue;
            target[PATH_BUF - 1] = '\0';

            unsigned li;
            if (sscanf(target, "socket:[%u]", &li) == 1 && li == inode) {
                int pid = atoi(de->d_name);
                closedir(fd_dir);
                closedir(proc);
                return pid;
            }
        }
        closedir(fd_dir);
    }
    closedir(proc);
    return -1;
}

static void get_process_name(int pid, char *buf, size_t sz)
{
    if (sz == 0) return;
    buf[0] = '\0';

    char path[PATH_BUF];
    snprintf(path, PATH_BUF, "/proc/%d/cmdline", pid);

    FILE *f = fopen(path, "r");
    if (f) {
        size_t n = fread(buf, 1, sz - 1, f);
        fclose(f);
        if (n > 0) {
            buf[n] = '\0';
            for (size_t i = 0; i + 1 < n; i++) {
                if (buf[i] == '\0') buf[i] = ' ';
            }
            while (n > 0 && (buf[n - 1] == '\0' || isspace((unsigned char)buf[n - 1])))
                buf[--n] = '\0';
            if (buf[0] != '\0') return;
        }
    }

    snprintf(path, PATH_BUF, "/proc/%d/comm", pid);
    f = fopen(path, "r");
    if (f) {
        if (fgets(buf, (int)sz, f)) {
            size_t n = strlen(buf);
            while (n > 0 && (buf[n-1]=='\n' || buf[n-1]=='\r'))
                buf[--n] = '\0';
        }
        fclose(f);
    }
    if (buf[0] == '\0')
        snprintf(buf, sz, "<pid %d>", pid);
}

/* ------------------------------------------------------------------ */
/*  Linux: collect + resolve                                          */
/* ------------------------------------------------------------------ */

static int collect_sockets(SocketEntry *entries, int cap,
                           ProtoFilter pf, StateFilter sf)
{
    int count = 0;

    if (matches_proto(PROTO_TCP, pf)) {
        count += parse_proc_net("/proc/net/tcp",  PROTO_TCP,
                                entries + count, cap - count);
        count += parse_proc_net("/proc/net/tcp6", PROTO_TCP,
                                entries + count, cap - count);
    }
    if (matches_proto(PROTO_UDP, pf)) {
        count += parse_proc_net("/proc/net/udp",  PROTO_UDP,
                                entries + count, cap - count);
        count += parse_proc_net("/proc/net/udp6", PROTO_UDP,
                                entries + count, cap - count);
    }

    /* Resolve inodes → PIDs. */
    for (int i = 0; i < count; i++) {
        if (entries[i].inode == 0) continue;
        entries[i].pid = find_pid_by_inode(entries[i].inode);
        if (entries[i].pid > 0)
            get_process_name(entries[i].pid, entries[i].process,
                             sizeof(entries[i].process));
    }

    /* Filter by state. */
    int out = 0;
    for (int i = 0; i < count; i++) {
        if (matches_state(entries[i].state, sf))
            entries[out++] = entries[i];
    }
    return out;
}

/* ================================================================== */
/* ------------------------------------------------------------------ */
/*  macOS BACKEND  (libproc.h, no external applications)              */
/* ------------------------------------------------------------------ */

#elif defined(__APPLE__)

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

static void get_process_name(pid_t pid, char *buf, size_t bufsz)
{
    if (bufsz == 0) return;
    buf[0] = '\0';

    char short_name[NAME_BUF] = {0};
    proc_name(pid, short_name, sizeof(short_name));
    short_name[sizeof(short_name) - 1] = '\0';

    int mib[] = {CTL_KERN, KERN_PROCARGS2, (int)pid};
    size_t argmax = ARG_MAX;
    char *args = malloc(argmax);

    if (args && sysctl(mib, 3, args, &argmax, NULL, 0) == 0 &&
        argmax > sizeof(int)) {
        int argc = 0;
        memcpy(&argc, args, sizeof(argc));

        char cmdline[NAME_BUF] = {0};
        char *p = args + sizeof(int);
        char *end = args + argmax;

        while (p < end && *p != '\0') p++; /* executable path */
        while (p < end && *p == '\0') p++;

        for (int i = 0; i < argc && p < end && *p != '\0'; i++) {
            if (i > 0) append_text(cmdline, sizeof(cmdline), " ");
            append_text(cmdline, sizeof(cmdline), p);
            while (p < end && *p != '\0') p++;
            while (p < end && *p == '\0') p++;
        }

        if (cmdline[0] != '\0') {
            char first[NAME_BUF] = {0};
            size_t n = strcspn(cmdline, " \t");
            if (n >= sizeof(first)) n = sizeof(first) - 1;
            memcpy(first, cmdline, n);
            first[n] = '\0';

            const char *base = strrchr(first, '/');
            base = base ? base + 1 : first;

            if (short_name[0] != '\0' && strcmp(short_name, base) != 0)
                snprintf(buf, bufsz, "%s: %s", short_name, cmdline);
            else
                snprintf(buf, bufsz, "%s", cmdline);
            buf[bufsz - 1] = '\0';
            free(args);
            return;
        }
    }
    free(args);

    char path[PROC_PIDPATHINFO_MAXSIZE];
    if (proc_pidpath(pid, path, sizeof(path)) > 0) {
        strncpy(buf, path, bufsz - 1);
        buf[bufsz - 1] = '\0';
        return;
    }

    if (short_name[0] != '\0') {
        strncpy(buf, short_name, bufsz - 1);
        buf[bufsz - 1] = '\0';
        return;
    }

    snprintf(buf, bufsz, "<pid %d>", pid);
}

static const char *mac_tcp_state_name(int state)
{
    switch (state) {
        case TSI_S_CLOSED:       return "CLOSED";
        case TSI_S_LISTEN:       return "LISTEN";
        case TSI_S_SYN_SENT:     return "SYN_SENT";
        case TSI_S_SYN_RECEIVED: return "SYN_RECV";
        case TSI_S_ESTABLISHED:  return "ESTABLISHED";
        case TSI_S__CLOSE_WAIT:  return "CLOSE_WAIT";
        case TSI_S_FIN_WAIT_1:   return "FIN_WAIT1";
        case TSI_S_CLOSING:      return "CLOSING";
        case TSI_S_LAST_ACK:     return "LAST_ACK";
        case TSI_S_FIN_WAIT_2:   return "FIN_WAIT2";
        case TSI_S_TIME_WAIT:    return "TIME_WAIT";
        default:                 return "UNKNOWN";
    }
}

static void mac_addr_to_str(const struct in_sockinfo *insi,
                            int local,
                            char *addr_buf,
                            size_t addr_sz,
                            int *port_out)
{
    const void *addr = NULL;
    int family = AF_UNSPEC;

    if (local)
        *port_out = (int)ntohs((uint16_t)insi->insi_lport);
    else
        *port_out = (int)ntohs((uint16_t)insi->insi_fport);

    if (insi->insi_vflag & INI_IPV4) {
        const struct in_addr *a4 = local
            ? &insi->insi_laddr.ina_46.i46a_addr4
            : &insi->insi_faddr.ina_46.i46a_addr4;
        if (a4->s_addr == 0) {
            strcpy(addr_buf, "*");
            return;
        }
        addr = a4;
        family = AF_INET;
    } else if (insi->insi_vflag & INI_IPV6) {
        const struct in6_addr *a6 = local
            ? &insi->insi_laddr.ina_6
            : &insi->insi_faddr.ina_6;
        if (IN6_IS_ADDR_UNSPECIFIED(a6)) {
            strcpy(addr_buf, "*");
            return;
        }
        addr = a6;
        family = AF_INET6;
    }

    if (!addr || !inet_ntop(family, addr, addr_buf, (socklen_t)addr_sz))
        strcpy(addr_buf, "*");
}

static int add_macos_socket(SocketEntry *entries, int cap, int count,
                            pid_t pid, const char *process,
                            const struct socket_fdinfo *sfi,
                            ProtoFilter pf, StateFilter sf)
{
    const struct socket_info *si = &sfi->psi;
    const struct in_sockinfo *insi = NULL;
    Proto proto;
    const char *state = "BOUND";

    if (si->soi_family != AF_INET && si->soi_family != AF_INET6)
        return count;

    if (si->soi_protocol == IPPROTO_TCP || si->soi_kind == SOCKINFO_TCP) {
        proto = PROTO_TCP;
        insi = &si->soi_proto.pri_tcp.tcpsi_ini;
        state = mac_tcp_state_name(si->soi_proto.pri_tcp.tcpsi_state);
    } else if (si->soi_protocol == IPPROTO_UDP || si->soi_kind == SOCKINFO_IN) {
        proto = PROTO_UDP;
        insi = &si->soi_proto.pri_in;
        state = "BOUND";
    } else {
        return count;
    }

    if (!matches_proto(proto, pf) || !matches_state(state, sf))
        return count;

    if (count >= cap)
        return count;

    char laddr[64] = {0};
    char raddr[64] = {0};
    int lport = 0;
    int rport = 0;

    mac_addr_to_str(insi, 1, laddr, sizeof(laddr), &lport);
    mac_addr_to_str(insi, 0, raddr, sizeof(raddr), &rport);

    if (lport == 0)
        return count;

    for (int i = 0; i < count; i++) {
        if (entries[i].pid == (int)pid &&
            entries[i].proto == proto &&
            entries[i].local_port == lport &&
            entries[i].remote_port == rport &&
            strcmp(entries[i].local_addr, laddr) == 0 &&
            strcmp(entries[i].remote_addr, raddr) == 0 &&
            strcmp(entries[i].state, state) == 0) {
            return count;
        }
    }

    entries[count].proto = proto;
    strncpy(entries[count].local_addr, laddr,
            sizeof(entries[count].local_addr) - 1);
    entries[count].local_port = lport;
    strncpy(entries[count].remote_addr, raddr,
            sizeof(entries[count].remote_addr) - 1);
    entries[count].remote_port = rport;
    strncpy(entries[count].state, state,
            sizeof(entries[count].state) - 1);
    entries[count].inode = 0;
    entries[count].pid = (int)pid;
    strncpy(entries[count].process, process,
            sizeof(entries[count].process) - 1);

    return count + 1;
}

/* ------------------------------------------------------------------ */
/*  macOS: collect sockets by walking processes and socket FDs         */
/* ------------------------------------------------------------------ */

static int collect_sockets(SocketEntry *entries, int cap,
                           ProtoFilter pf, StateFilter sf)
{
    int pid_bytes = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    if (pid_bytes <= 0)
        return 0;

    pid_t *pids = malloc((size_t)pid_bytes);
    if (!pids) {
        fprintf(stderr, "portwho: out of memory\n");
        return 0;
    }

    pid_bytes = proc_listpids(PROC_ALL_PIDS, 0, pids, pid_bytes);
    if (pid_bytes <= 0) {
        free(pids);
        return 0;
    }

    int pid_count = pid_bytes / (int)sizeof(pid_t);
    int count = 0;

    for (int i = 0; i < pid_count && count < cap; i++) {
        pid_t pid = pids[i];
        if (pid <= 0)
            continue;

        int fd_bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
        if (fd_bytes <= 0)
            continue;

        struct proc_fdinfo *fds = malloc((size_t)fd_bytes);
        if (!fds)
            continue;

        fd_bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, fd_bytes);
        if (fd_bytes <= 0) {
            free(fds);
            continue;
        }

        char process[NAME_BUF] = {0};
        get_process_name(pid, process, sizeof(process));

        int fd_count = fd_bytes / (int)PROC_PIDLISTFD_SIZE;
        for (int j = 0; j < fd_count && count < cap; j++) {
            if (fds[j].proc_fdtype != PROX_FDTYPE_SOCKET)
                continue;

            struct socket_fdinfo sfi;
            int got = proc_pidfdinfo(pid, fds[j].proc_fd,
                                     PROC_PIDFDSOCKETINFO,
                                     &sfi, sizeof(sfi));
            if (got != PROC_PIDFDSOCKETINFO_SIZE)
                continue;

            count = add_macos_socket(entries, cap, count, pid, process,
                                     &sfi, pf, sf);
        }

        free(fds);
    }

    free(pids);
    return count;
}

#endif /* __APPLE__ */
    
/* ================================================================== */
/*  Main                                                              */
/* ================================================================== */

int main(int argc, char *argv[])
{
    ProtoFilter proto_filter = FILTER_ALL;
    StateFilter state_filter = STATE_ALL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--tcp") == 0) {
            proto_filter = FILTER_TCP;
        } else if (strcmp(argv[i], "--udp") == 0) {
            proto_filter = FILTER_UDP;
        } else if (strcmp(argv[i], "--all") == 0) {
            proto_filter = FILTER_ALL;
        } else if (strcmp(argv[i], "--listening") == 0) {
            state_filter = STATE_LISTEN;
        } else if (strcmp(argv[i], "--established") == 0) {
            state_filter = STATE_ESTABLISHED;
        } else if (strcmp(argv[i], "--all-states") == 0) {
            state_filter = STATE_ALL;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    SocketEntry entries[MAX_ENTRIES];
    int count = collect_sockets(entries, MAX_ENTRIES,
                                proto_filter, state_filter);

    int width = terminal_width();
    OutputMode output_mode = output_mode_for_width(width);

    print_header(output_mode, width);
    int printed = 0;
    for (int i = 0; i < count; i++) {
        print_entry(&entries[i], output_mode, width);
        printed++;
    }

    printf("\n%d socket(s) shown.\n", printed);
    return 0;
}

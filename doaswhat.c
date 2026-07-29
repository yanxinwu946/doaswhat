/*
 * doaswhat-cfast - Fast doas permission enumerator (C, parallel fork)
 * v2.0 - https://github.com/yanxinwu946/doaswhat
 *
 * Forks ALL test children at once, polls with waitpid(WNOHANG) on a
 * deadline. Exit-0 before deadline = nopass; still alive at deadline
 * = killed and classified as "password required".
 *
 * Build: x86_64-linux-gnu-gcc -O2 -s -static -o doaswhat-cfast doaswhat-cfast.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

#define VERSION     "v2.0"
#define TIMEOUT_MS  600

static const char *C_RST = "\033[0m";
static const char *C_RED = "\033[31m";
static const char *C_GRN = "\033[32m";
static const char *C_YEL = "\033[33m";
static const char *C_GRY = "\033[90m";
static const char *C_BLD = "\033[1m";

static void setup_colors(void) {
    if (getenv("NO_COLOR") || (getenv("CLICOLOR") && !strcmp(getenv("CLICOLOR"), "0")))
        C_RST = C_RED = C_GRN = C_YEL = C_GRY = C_BLD = "";
    if (!isatty(STDOUT_FILENO) && !getenv("CLICOLOR_FORCE"))
        C_RST = C_RED = C_GRN = C_YEL = C_GRY = C_BLD = "";
}

typedef struct { char **items; size_t cnt, cap; } Strs;

static void strs_add(Strs *s, const char *val) {
    if (s->cnt >= s->cap) {
        s->cap = s->cap ? s->cap * 2 : 256;
        s->items = realloc(s->items, s->cap * sizeof(char *));
    }
    s->items[s->cnt++] = strdup(val);
}

static int strs_cmp(const void *a, const void *b) {
    return strcmp(*(const char **)a, *(const char **)b);
}

typedef struct {
    pid_t  pid;
    char  *cmd;
    int    exited;
    int    exitcode;
} Child;

static void banner(void) {
    printf("doaswhat %s  %sSublarge%s  %shttps://github.com/yanxinwu946/doaswhat%s\n",
           VERSION, C_BLD, C_RST, C_GRY, C_RST);
}

static void show_help(void) {
    banner();
    printf("\nUsage: doaswhat [-u user] [-h]\n\n");
    printf("Enumerate doas permission rules by probing every\n");
    printf("executable in  (full-path + basename).\n\n");
    printf("Flags:\n");
    printf("  -u user   test permissions for a given user\n");
    printf("  -h        show this help\n");
}

static char *find_doas(void) {
    char *path_env = getenv("PATH");
    if (!path_env) return NULL;
    char *cpy = strdup(path_env), *save, *dir, *res = NULL;
    for (dir = strtok_r(cpy, ":", &save); dir; dir = strtok_r(NULL, ":", &save)) {
        size_t len = strlen(dir) + 6;
        char *full = malloc(len);
        if (!full) continue;
        snprintf(full, len, "%s/doas", dir);
        if (access(full, X_OK) == 0) { res = full; break; }
        free(full);
    }
    free(cpy);
    return res;
}

static void print_config(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return;
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    if (sz <= 0) { fclose(fp); return; }
    fseek(fp, 0, SEEK_SET);
    char *buf = malloc(sz + 1);
    if (!buf) { fclose(fp); return; }
    fread(buf, 1, sz, fp);
    buf[sz] = '\0';
    fclose(fp);
    printf("%s[+]%s %s\n", C_GRN, C_RST, path);
    for (char *l = strtok(buf, "\n"); l; l = strtok(NULL, "\n")) {
        while (*l == ' ' || *l == '\t') l++;
        if (*l) printf("    %s\n", l);
    }
    free(buf);
}

static Strs collect_exes(void) {
    Strs s = {NULL, 0, 0};
    char *path_env = getenv("PATH");
    if (!path_env) return s;
    char *cpy = strdup(path_env), *save, *dir;
    for (dir = strtok_r(cpy, ":", &save); dir; dir = strtok_r(NULL, ":", &save)) {
        DIR *dp = opendir(dir);
        if (!dp) continue;
        struct dirent *e;
        while ((e = readdir(dp))) {
            if (e->d_name[0] == '.') continue;
            size_t plen = strlen(dir) + strlen(e->d_name) + 2;
            char *full = malloc(plen);
            snprintf(full, plen, "%s/%s", dir, e->d_name);
            struct stat st;
            if (stat(full, &st) == 0 && S_ISREG(st.st_mode) && (st.st_mode & 0111)) {
                if (s.cnt >= s.cap) {
                    s.cap = s.cap ? s.cap * 2 : 1024;
                    s.items = realloc(s.items, s.cap * sizeof(char *));
                }
                s.items[s.cnt++] = full;
                full = NULL;
            }
            free(full);
        }
        closedir(dp);
    }
    free(cpy);
    return s;
}

static void print_ls_like(const char *path, struct stat *st) {
    char mode[11];
    mode[0] = S_ISDIR(st->st_mode) ? 'd' : '-';
    for (int i = 0; i < 9; i++) {
        int shift = 8 - i;
        mode[1 + i] = (st->st_mode & (1 << shift)) ? "rwxrwxrwx"[i] : '-';
    }
    if (st->st_mode & S_ISUID) mode[3] = (mode[3] == 'x') ? 's' : 'S';
    if (st->st_mode & S_ISGID) mode[6] = (mode[6] == 'x') ? 's' : 'S';
    mode[10] = '\0';
    char date[20];
    strftime(date, sizeof(date), "%b %e %Y", localtime(&st->st_mtime));
    printf("%s %lu %s %s %5lu %s %s\n",
           mode, (unsigned long)st->st_nlink,
           "root", "root",
           (unsigned long)st->st_size,
           date, path);
}

static long now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000L + tv.tv_usec / 1000;
}

int main(int argc, char *argv[]) {
    char *user = NULL;
    int help = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-u") && i + 1 < argc) user = argv[++i];
        else if (!strcmp(argv[i], "-h")) help = 1;
        else { show_help(); return 1; }
    }

    setup_colors();
    if (help) { show_help(); return 0; }

    banner();
    printf("\n");

    char *doas_path = find_doas();
    if (!doas_path) {
        printf("%s!%s doas not found\n", C_RED, C_RST);
        return 1;
    }

    printf("%s[*]%s binary\n", C_BLD, C_RST);
    struct stat st;
    if (stat(doas_path, &st) == 0)
        print_ls_like(doas_path, &st);
    else
        printf("%s\n", doas_path);
    printf("\n");

    if (user) {
        printf("%s[*]%s user\n", C_BLD, C_RST);
        printf("%s\n\n", user);
    }

    printf("%s[*]%s configs\n", C_BLD, C_RST);
    print_config("/etc/doas.conf");
    print_config("/usr/local/etc/doas.conf");
    DIR *dd = opendir("/etc/doas.d");
    if (dd) {
        struct dirent *de;
        while ((de = readdir(dd))) {
            size_t l = strlen(de->d_name);
            if (l > 5 && !strcmp(de->d_name + l - 5, ".conf")) {
                char p[512];
                snprintf(p, sizeof(p), "/etc/doas.d/%s", de->d_name);
                print_config(p);
            }
        }
        closedir(dd);
    }

    Strs exes = collect_exes();
    size_t n_exe = exes.cnt;
    printf("\n%s[*]%s probing %zu commands...\n", C_BLD, C_RST, n_exe);

    int argc_tmpl = 1 + (user ? 2 : 0) + 3;
    const char **argv_tmpl = calloc(argc_tmpl, sizeof(char *));
    int ai = 0;
    argv_tmpl[ai++] = doas_path;
    if (user) { argv_tmpl[ai++] = "-u"; argv_tmpl[ai++] = user; }
    argv_tmpl[ai + 2] = NULL;
    int slot_cmd = ai, slot_help = ai + 1;

    Child *children = calloc(n_exe * 2, sizeof(Child));
    if (!children) { perror("calloc"); return 1; }
    size_t ci = 0;

    sigset_t mask, oldmask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &mask, &oldmask);

    int devnull = open("/dev/null", O_RDWR);
    long t_start = now_ms();

    for (size_t i = 0; i < n_exe; i++) {
        char *full = exes.items[i];
        char *base = strrchr(full, '/');
        base = base ? base + 1 : full;

        argv_tmpl[slot_cmd] = full;
        argv_tmpl[slot_help] = "--help";
        pid_t p = fork();
        if (p == 0) {
            if (devnull >= 0) {
                dup2(devnull, STDIN_FILENO);
                dup2(devnull, STDOUT_FILENO);
                dup2(devnull, STDERR_FILENO);
            }
            execvp(doas_path, (char *const *)argv_tmpl);
            _exit(126);
        }
        if (p > 0) {
            children[ci].pid = p;
            children[ci].cmd = full;
            children[ci].exited = 0;
            ci++;
        }

        argv_tmpl[slot_cmd] = base;
        p = fork();
        if (p == 0) {
            if (devnull >= 0) {
                dup2(devnull, STDIN_FILENO);
                dup2(devnull, STDOUT_FILENO);
                dup2(devnull, STDERR_FILENO);
            }
            execvp(doas_path, (char *const *)argv_tmpl);
            _exit(126);
        }
        if (p > 0) {
            children[ci].pid = p;
            children[ci].cmd = base;
            children[ci].exited = 0;
            ci++;
        }

        if ((i & 31) == 0) {
            printf("\r%s[%zu/%zu]%s testing...", C_GRY, i + 1, n_exe, C_RST);
            fflush(stdout);
        }
    }
    if (devnull >= 0) close(devnull);

    printf("\r%s[%zu/%zu]%s testing...\n", C_GRY, n_exe, n_exe, C_RST);
    sigprocmask(SIG_SETMASK, &oldmask, NULL);

    long deadline = now_ms() + TIMEOUT_MS;
    size_t reaped = 0;
    while (reaped < ci) {
        long remaining = deadline - now_ms();
        if (remaining <= 0) break;
        int status;
        pid_t w = waitpid(-1, &status, WNOHANG);
        if (w > 0) {
            for (size_t j = 0; j < ci; j++) {
                if (children[j].pid == w) {
                    children[j].exited = 1;
                    children[j].exitcode = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
                    reaped++;
                    break;
                }
            }
        } else if (w == 0) {
            usleep(remaining > 10000 ? 10000 : remaining);
        } else {
            if (errno == ECHILD) break;
        }
    }

    for (size_t j = 0; j < ci; j++) {
        if (!children[j].exited) {
            kill(children[j].pid, SIGKILL);
            waitpid(children[j].pid, NULL, 0);
        }
    }

    Strs nopass = {NULL, 0, 0}, pass = {NULL, 0, 0};
    for (size_t j = 0; j < ci; j++) {
        if (!children[j].exited) {
            int seen = 0;
            for (size_t k = 0; k < pass.cnt; k++)
                if (!strcmp(pass.items[k], children[j].cmd)) { seen = 1; break; }
            for (size_t k = 0; k < nopass.cnt && !seen; k++)
                if (!strcmp(nopass.items[k], children[j].cmd)) { seen = 1; break; }
            if (!seen) strs_add(&pass, children[j].cmd);
        } else if (children[j].exitcode == 0) {
            int seen = 0;
            for (size_t k = 0; k < nopass.cnt; k++)
                if (!strcmp(nopass.items[k], children[j].cmd)) { seen = 1; break; }
            if (!seen) strs_add(&nopass, children[j].cmd);
        }
    }

    long elapsed = now_ms() - t_start;
    printf("%s[*]%s analyzing results...\n", C_BLD, C_RST);

    if (nopass.cnt == 0 && pass.cnt == 0) {
        printf("%s!%s no commands allowed via doas\n", C_RED, C_RST);
        goto cleanup;
    }

    qsort(nopass.items, nopass.cnt, sizeof(char *), strs_cmp);
    qsort(pass.items, pass.cnt, sizeof(char *), strs_cmp);

    const char *pfx = "doas";
    char pfx_buf[256];
    if (user) { snprintf(pfx_buf, sizeof(pfx_buf), "doas -u %s", user); pfx = pfx_buf; }

if (nopass.cnt) {
        printf("\n%s[+]%s you can run these without a password:\n", C_GRN, C_RST);
        for (size_t i = 0; i < nopass.cnt; i++)
            printf("    %s %s\n", pfx, nopass.items[i]);
    }
    if (pass.cnt) {
        printf("\n%s[!]%s these require a password:\n", C_YEL, C_RST);
        for (size_t i = 0; i < pass.cnt; i++)
            printf("    %s %s\n", pfx, pass.items[i]);
    }
    printf("\n");

cleanup:
    free(doas_path);
    free(argv_tmpl);
    free(children);
    for (size_t i = 0; i < exes.cnt; i++) free(exes.items[i]);
    free(exes.items);
    for (size_t i = 0; i < nopass.cnt; i++) free(nopass.items[i]);
    free(nopass.items);
    for (size_t i = 0; i < pass.cnt; i++) free(pass.items[i]);
    free(pass.items);
    return 0;
}

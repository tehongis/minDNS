/* main.c – DNS forwarder that uses the cache from cache.c */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <stdarg.h>

#include "cache.h"

/* ------------------------------------------------------------------
 * Global state for configuration and logging.
 * ------------------------------------------------------------------ */
static FILE *log_file = NULL;
static volatile sig_atomic_t stop_flag = 0;
static volatile sig_atomic_t reload_flag = 0;

typedef struct {
    char upstream_ip[16];
    unsigned short upstream_port;
    char listen_ip[16];
    unsigned short listen_port;
    char blocklist_file[256];
    char cache_file[256];
    char log_file_path[256];
    int daemonize;
    size_t max_cache_size;
} Config;

/* ------------------------------------------------------------------
 * Logging functions.
 * ------------------------------------------------------------------ */
static void init_logging(const char *log_path)
{
    if (log_file && log_file != stdout) {
        fclose(log_file);
    }

    if (log_path && strlen(log_path) > 0) {
        log_file = fopen(log_path, "a");
        if (!log_file) {
            perror("fopen(log_file)");
            log_file = stdout;
        }
    } else {
        log_file = stdout;
    }
}

static void log_msg(const char *fmt, ...)
{
    if (!log_file) log_file = stdout;

    va_list args;
    va_start(args, fmt);

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(log_file, "[%s] ", timestamp);
    vfprintf(log_file, fmt, args);
    fprintf(log_file, "\n");
    fflush(log_file);

    va_end(args);
}

/* ------------------------------------------------------------------
 * Configuration file parsing.
 * ------------------------------------------------------------------ */
static const char *config_file = "minDNS.config";

static Config load_config(void)
{
    Config cfg = {
        .upstream_ip = "8.8.8.8",
        .upstream_port = 53,
        .listen_ip = "127.0.0.1",
        .listen_port = 53,
        .blocklist_file = "minDNS.block",
        .cache_file = "minDNS.cache",
        .log_file_path = "",
        .daemonize = 0,
        .max_cache_size = 10000
    };

    FILE *f = fopen(config_file, "r");
    if (!f) {
        log_msg("Warning: %s not found, using defaults", config_file);
        return cfg;
    }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        /* Remove newline */
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        /* Skip empty lines and comments */
        if (line[0] == '#' || line[0] == '\0')
            continue;

        /* Parse key=value pairs */
        char *eq = strchr(line, '=');
        if (!eq) continue;

        *eq = '\0';
        char *key = line;
        char *value = eq + 1;

        /* Trim whitespace */
        while (*key && (*key == ' ' || *key == '\t')) key++;
        while (*value && (*value == ' ' || *value == '\t')) value++;

        if (strcmp(key, "upstream_ip") == 0) {
            strncpy(cfg.upstream_ip, value, sizeof(cfg.upstream_ip) - 1);
        } else if (strcmp(key, "upstream_port") == 0) {
            cfg.upstream_port = (unsigned short)atoi(value);
        } else if (strcmp(key, "listen_ip") == 0) {
            strncpy(cfg.listen_ip, value, sizeof(cfg.listen_ip) - 1);
        } else if (strcmp(key, "listen_port") == 0) {
            cfg.listen_port = (unsigned short)atoi(value);
        } else if (strcmp(key, "blocklist_file") == 0) {
            strncpy(cfg.blocklist_file, value, sizeof(cfg.blocklist_file) - 1);
        } else if (strcmp(key, "cache_file") == 0) {
            strncpy(cfg.cache_file, value, sizeof(cfg.cache_file) - 1);
        } else if (strcmp(key, "log_file") == 0) {
            strncpy(cfg.log_file_path, value, sizeof(cfg.log_file_path) - 1);
        } else if (strcmp(key, "daemonize") == 0) {
            cfg.daemonize = (atoi(value) != 0);
        } else if (strcmp(key, "max_cache_size") == 0) {
            cfg.max_cache_size = (size_t)atoi(value);
        }
    }

    fclose(f);
    return cfg;
}

/* ------------------------------------------------------------------
 * Daemonize the process.
 * ------------------------------------------------------------------ */
static void daemonize(void)
{
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork()");
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);  /* parent exits */
    }

    /* Child continues */
    if (setsid() < 0) {
        perror("setsid()");
        exit(EXIT_FAILURE);
    }

    (void)chdir("/");

    /* Close standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    /* Redirect to /dev/null */
    int fd = open("/dev/null", O_RDWR);
    if (fd != -1) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > 2) close(fd);
    }
}

/* ------------------------------------------------------------------
 * Block‑list handling.
 * ------------------------------------------------------------------ */
static char **blocklist = NULL;
static size_t blocklist_count = 0;

static void load_blocklist(const char *filename)
{
    FILE *f = fopen(filename, "r");
    if (!f) {
        log_msg("Error: Cannot open blocklist file %s", filename);
        exit(EXIT_FAILURE);
    }

    /* Count lines first – simple two‑pass approach */
    size_t lines = 0;
    char *line = NULL;
    size_t sz = 0;
    while (getline(&line, &sz, f) != -1) {
        /* Skip comments and empty lines */
        if (line[0] != '#' && line[0] != '\0' && line[0] != '\n')
            ++lines;
    }
    rewind(f);

    blocklist = calloc(lines, sizeof(char *));
    if (!blocklist) {
        perror("calloc()");
        exit(EXIT_FAILURE);
    }
    blocklist_count = lines;

    line = NULL;
    sz = 0;
    size_t idx = 0;
    for (size_t i = 0; i < lines; ++i) {
        if (getline(&line, &sz, f) == -1) break;
        
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\n') {
            ++i;
            continue;
        }

        /* strip CR/LF */
        char *p = strchr(line, '\n');
        if (p) *p = '\0';
        p = strchr(line, '\r');
        if (p) *p = '\0';
        
        blocklist[idx++] = strdup(line);
    }
    blocklist_count = idx;  /* Update actual count */
    free(line);
    fclose(f);
    log_msg("Loaded blocklist: %zu domains", blocklist_count);
}

/* ------------------------------------------------------------------
 * Cleanup blocklist.
 * ------------------------------------------------------------------ */
static void cleanup_blocklist(void)
{
    for (size_t i = 0; i < blocklist_count; ++i)
        free(blocklist[i]);
    free(blocklist);
    blocklist = NULL;
    blocklist_count = 0;
}

/* ------------------------------------------------------------------
 * DNS query parsing – extract domain name from DNS query packet.
 * ------------------------------------------------------------------ */
static int parse_dns_query(const unsigned char *query, size_t query_len,
                           char *domain, size_t domain_size)
{
    if (query_len < 12) return -1;  /* DNS header is 12 bytes minimum */

    /* Skip the 12-byte header and parse the question section */
    size_t pos = 12;
    size_t domain_pos = 0;

    while (pos < query_len && domain_pos < domain_size - 1) {
        unsigned char len = query[pos++];
        if (len == 0) break;        /* end of domain name */
        if (len > 63) return -1;    /* invalid label length */

        if (domain_pos > 0)
            domain[domain_pos++] = '.';

        if (domain_pos + len >= domain_size) return -1;
        memcpy(&domain[domain_pos], &query[pos], len);
        domain_pos += len;
        pos += len;
    }

    domain[domain_pos] = '\0';
    return 0;
}

/* ------------------------------------------------------------------
 * Check if domain is in the blocklist (with wildcard support).
 * ------------------------------------------------------------------ */
static int is_blocked(const char *domain)
{
    for (size_t i = 0; i < blocklist_count; ++i) {
        const char *pattern = blocklist[i];
        
        /* Exact match */
        if (strcasecmp(domain, pattern) == 0)
            return 1;
        
        /* Wildcard match: *.example.com matches sub.example.com */
        if (pattern[0] == '*' && pattern[1] == '.') {
            const char *suffix = pattern + 1;  /* skip the '*' */
            size_t suffix_len = strlen(suffix);
            size_t domain_len = strlen(domain);
            
            if (domain_len > suffix_len) {
                const char *domain_suffix = domain + domain_len - suffix_len;
                if (strcasecmp(domain_suffix, suffix) == 0)
                    return 1;
            }
        }
    }
    return 0;
}

/* ------------------------------------------------------------------
 * Create a DNS NXDOMAIN response (domain not found).
 * ------------------------------------------------------------------ */
static void create_nxdomain_response(const unsigned char *query,
                                     size_t query_len,
                                     unsigned char **reply,
                                     size_t *reply_len)
{
    *reply = malloc(query_len);
    if (!*reply) return;

    memcpy(*reply, query, query_len);

    /* Set QR bit (response) and RCODE to 3 (NXDOMAIN) */
    (*reply)[2] |= 0x80;            /* QR bit */
    (*reply)[3] = ((*reply)[3] & 0xF0) | 3;  /* RCODE = 3 */

    *reply_len = query_len;
}

/* ------------------------------------------------------------------
 * Forward a query to the upstream server and read the reply.
 * ------------------------------------------------------------------ */
static int forward_to_upstream(const unsigned char *query,
                               size_t query_len,
                               unsigned char **reply,
                               size_t *reply_len,
                               const char *upstream_ip,
                               unsigned short upstream_port)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in srv = { 0 };
    srv.sin_family      = AF_INET;
    srv.sin_port        = htons(upstream_port);
    if (inet_pton(AF_INET, upstream_ip, &srv.sin_addr) != 1) {
        close(sock);
        return -1;
    }

    if (sendto(sock, query, query_len, 0,
               (struct sockaddr *)&srv, sizeof(srv)) != (ssize_t)query_len) {
        close(sock);
        return -1;
    }

    /* we expect the reply to be < 512 bytes (standard UDP DNS) */
    unsigned char buf[512];
    ssize_t n = recv(sock, buf, sizeof(buf), 0);
    close(sock);
    if (n <= 0) return -1;

    *reply     = malloc(n);
    if (!*reply) {
        perror("malloc()");
        return -1;
    }
    memcpy(*reply, buf, n);
    *reply_len = (size_t)n;
    return 0;
}

/* ------------------------------------------------------------------
 * Extract TTL from DNS response.
 * ------------------------------------------------------------------ */
static unsigned int extract_ttl_from_reply(const unsigned char *reply, size_t reply_len)
{
    unsigned int default_ttl = 300;  /* 5 minutes */

    if (reply_len < 12)
        return default_ttl;

    /* Skip to answer section (simplified – assumes standard format) */
    size_t pos = 12;

    /* Skip questions */
    unsigned short qdcount = (reply[4] << 8) | reply[5];
    for (unsigned short i = 0; i < qdcount && pos < reply_len; ++i) {
        while (pos < reply_len && reply[pos] != 0) {
            if (reply[pos] >= 192) {  /* label pointer */
                pos += 2;
                break;
            }
            pos += reply[pos] + 1;
        }
        pos += 5;  /* null byte + type + class */
    }

    /* Read first answer's TTL */
    if (pos + 10 < reply_len) {
        unsigned int ttl = (reply[pos + 6] << 24) |
                          (reply[pos + 7] << 16) |
                          (reply[pos + 8] << 8) |
                          reply[pos + 9];
        return (ttl > 0) ? ttl : default_ttl;
    }

    return default_ttl;
}

/* ------------------------------------------------------------------
 * Forward a query – uses cache first, otherwise talks to upstream.
 * ------------------------------------------------------------------ */
static int forward_request(const unsigned char *query,
                           size_t query_len,
                           unsigned char **reply,
                           size_t *reply_len,
                           const char *upstream_ip,
                           unsigned short upstream_port,
                           size_t max_cache_size)
{
    /* 1) check cache */
    const CacheEntry *e = cache_lookup(query, query_len);
    if (e) {
        /* Cache hit – copy the cached reply back */
        *reply = malloc(e->reply_len);
        if (!*reply) {
            perror("malloc()");
            return -1;
        }
        memcpy(*reply, e->reply, e->reply_len);
        *reply_len = e->reply_len;
        return 0;
    }

    /* 2) not cached – forward to upstream */
    if (forward_to_upstream(query, query_len,
                            reply, reply_len,
                            upstream_ip, upstream_port) < 0)
        return -1;

    /* 3) store in cache with extracted TTL (if cache not full) */
    if (cache_size() < max_cache_size) {
        unsigned int ttl = extract_ttl_from_reply(*reply, *reply_len);
        cache_insert(query, query_len, *reply, *reply_len, ttl);
    }
    return 0;
}

/* ------------------------------------------------------------------
 * Signal handling – graceful shutdown and reload.
 * ------------------------------------------------------------------ */
static void sig_handler(int signo)
{
    if (signo == SIGINT || signo == SIGTERM) {
        stop_flag = 1;
    } else if (signo == SIGHUP) {
        reload_flag = 1;
    }
}

/* ------------------------------------------------------------------
 * Cache persistence – save and load cache to/from disk.
 * ------------------------------------------------------------------ */
static void load_cache_from_disk(const char *cache_filename)
{
    FILE *f = fopen(cache_filename, "rb");
    if (!f) {
        log_msg("Cache file %s not found, will create on exit", cache_filename);
        return;
    }

    log_msg("Loading cache from %s", cache_filename);

    size_t key_len, reply_len;
    unsigned int ttl;

    while (1) {
        /* Read key length */
        if (fread(&key_len, sizeof(key_len), 1, f) != 1)
            break;

        unsigned char key_buf[512];
        if (key_len > sizeof(key_buf)) break;
        if (fread(key_buf, key_len, 1, f) != 1)
            break;

        /* Read reply length */
        if (fread(&reply_len, sizeof(reply_len), 1, f) != 1)
            break;

        unsigned char reply_buf[512];
        if (reply_len > sizeof(reply_buf)) break;
        if (fread(reply_buf, reply_len, 1, f) != 1)
            break;

        /* Read TTL */
        if (fread(&ttl, sizeof(ttl), 1, f) != 1)
            break;

        /* Insert into cache with TTL */
        cache_insert(key_buf, key_len, reply_buf, reply_len, ttl);
    }

    fclose(f);
    log_msg("Cache loaded");
}

static void save_cache_to_disk(const char *cache_filename)
{
    FILE *f = fopen(cache_filename, "wb");
    if (!f) {
        log_msg("Error: Cannot save cache to %s", cache_filename);
        return;
    }

    log_msg("Saving cache to %s", cache_filename);
    cache_save(f);
    fclose(f);
    log_msg("Cache file created/updated: %s", cache_filename);
}

/* ------------------------------------------------------------------
 * Main entry point.
 * ------------------------------------------------------------------ */
int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    /* Load configuration */
    Config cfg = load_config();

    /* Initialize logging */
    init_logging(cfg.log_file_path);
    log_msg("minDNS starting...");

    /* Daemonize if requested */
    if (cfg.daemonize) {
        log_msg("Daemonizing...");
        daemonize();
        /* Re-initialize logging after fork */
        init_logging(cfg.log_file_path);
        log_msg("minDNS daemon started (PID: %d)", getpid());
    }

    /* Main server loop */
    while (!stop_flag) {
        /* Load configuration and blocklist */
        cache_init();
        load_cache_from_disk(cfg.cache_file);
        load_blocklist(cfg.blocklist_file);

        /* Install signal handlers */
        struct sigaction sa = { .sa_handler = sig_handler, .sa_flags = 0 };
        sigemptyset(&sa.sa_mask);
        sigaction(SIGINT, &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGHUP, &sa, NULL);

        /* Create listening socket */
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            log_msg("Error: Failed to create socket");
            exit(EXIT_FAILURE);
        }

        struct sockaddr_in local = { .sin_family = AF_INET,
                                     .sin_port   = htons(cfg.listen_port) };
        if (cfg.listen_ip[0] != '\0') {
             if (inet_pton(AF_INET, cfg.listen_ip, &local.sin_addr) != 1) {
                 log_msg("Error: Invalid listen IP");
                 close(sock);
                 exit(EXIT_FAILURE);
             }
         } else {
             local.sin_addr.s_addr = INADDR_ANY;
         }

        if (bind(sock, (struct sockaddr *)&local, sizeof(local)) < 0) {
            log_msg("Error: Failed to bind socket");
            close(sock);
            exit(EXIT_FAILURE);
        }

        log_msg("DNS forwarder listening on %s:%u, upstream %s:%u",
                cfg.listen_ip, cfg.listen_port,
                cfg.upstream_ip, cfg.upstream_port);

        /* Main event loop */
        unsigned char buf[512];
        reload_flag = 0;
        while (!stop_flag && !reload_flag) {
            struct sockaddr_in peer = { 0 };
            socklen_t peerlen = sizeof(peer);

            ssize_t n = recvfrom(sock, buf, sizeof(buf), 0,
                                 (struct sockaddr *)&peer, &peerlen);
            if (n < 0) {
                if (errno == EINTR) continue;
                log_msg("Error: recvfrom failed");
                break;
            }

            /* Parse domain and check block‑list */
            char domain[256] = { 0 };
            const unsigned char *reply = NULL;
            size_t reply_len = 0;

            if (parse_dns_query(buf, (size_t)n, domain, sizeof(domain)) == 0) {
                if (is_blocked(domain)) {
                    log_msg("[BLOCKED] %s from %s:%u",
                           domain,
                           inet_ntoa(peer.sin_addr),
                           ntohs(peer.sin_port));
                    create_nxdomain_response(buf, (size_t)n, (unsigned char **)&reply, &reply_len);
                    goto send_reply;
                }
            }

            /* Forward request */
            unsigned char *temp_reply = NULL;
            if (forward_request(buf, (size_t)n,
                                &temp_reply, &reply_len,
                                cfg.upstream_ip, cfg.upstream_port,
                                cfg.max_cache_size) < 0) {
                continue;
            }
            reply = temp_reply;

            /* Send back to client */
            send_reply:
            if (sendto(sock, reply, reply_len, 0,
                       (struct sockaddr *)&peer, peerlen) != (ssize_t)reply_len) {
                log_msg("Error: sendto failed");
            }

            free((void *)reply);
        }

        close(sock);

        /* Save cache */
        save_cache_to_disk(cfg.cache_file);
        cache_destroy();
        cleanup_blocklist();

        if (reload_flag) {
            log_msg("Reloading configuration...");
            cfg = load_config();
            init_logging(cfg.log_file_path);
            reload_flag = 0;
        }
    }

    log_msg("minDNS shutdown complete");
    if (log_file && log_file != stdout) {
        fclose(log_file);
    }
    return 0;
}

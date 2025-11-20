--- Current Functionalities ---
DNS Forwarding – Forwards queries to upstream DNS server
Caching – Caches DNS responses with TTL support
Cache Persistence – Saves/loads cache to/from disk
Blocklist – Blocks domains from blocklist file
Wildcard Blocking – Supports *.example.com patterns
Comments in Blocklist – Lines starting with # are ignored
NXDOMAIN Responses – Returns "not found" for blocked domains
Configuration File – Loads settings from minDNS.config
Logging – Logs to file with timestamps
Cache Size Limits – Respects max_cache_size setting
Signal Handling – SIGINT/SIGTERM for graceful shutdown
SIGHUP Reload – Hot reload config and blocklist without restart
Daemonize – Optional background service mode
TTL Support – Extracts and respects DNS TTL values
Cache Expiration – Automatically removes expired entries

--- Missing Functionalities ----
IPv6 Support – No AAAA records or IPv6 upstream servers
EDNS0 Support – No support for DNS extensions or large responses
Query Statistics – No detailed per-domain stats or reporting
Rate Limiting – No protection against DNS amplification attacks
Response Caching by Type – All queries cached same way (no A/AAAA/MX separation)
Reverse DNS (PTR) – No PTR query support
Multiple Upstream Servers – No failover or load balancing
Query Timeout – No configurable upstream query timeout
PID File – No PID file for systemd/init integration
Stats Endpoint – No way to query cache stats without recompiling
Query Logging – Only logs blocked domains, not all queries
Negative Caching – Doesn't cache NXDOMAIN responses
Response Validation – No DNSSEC or response validation
Concurrent Queries – Single-threaded, processes one query at a time
Memory Bounds – No hard memory limit, only entry count limit
Cache Compression – No compression of cached entries
Blocklist Reloading – Must reload all blocklist entries (no incremental)
Systemd Integration – No service file or socket activation


---- Priority Recommendations -----
High Priority:

Query logging (useful for debugging)
Negative caching (improves performance)
Multiple upstream servers with failover
Better error handling and recovery

Medium Priority:

Query timeout configuration
PID file support
IPv6 support
Rate limiting

Low Priority:

EDNS0 support
DNSSEC validation
Concurrent query handling (would require threading)
Statistics endpoint
--------------------------------------------------------------------

# Building & Running

```bash
gcc -Wall -Wextra -O2 -o dns_server dns_server.c cache.c
sudo ./dns_server
```

*You can also run under `sudo` or set the `cap_net_bind_service` capability if you want to avoid full root privileges:*

```bash
sudo setcap 'cap_net_bind_service=+ep' dns_server
./dns_server
```

Create a `blocklist.txt` in the same directory:
------------------
# Example comment
blocked.com
*.example.org
------------------

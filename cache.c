#include "cache.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#define CACHE_BUCKETS 256

/* The hash table itself */
static CacheEntry *table[CACHE_BUCKETS] = { NULL };

/* Stats */
static unsigned long cache_hits = 0;
static unsigned long cache_misses = 0;

/* ------------------------------------------------------------
 * Hash function for DNS query packets
 * ------------------------------------------------------------ */
static unsigned int hash_buf(const unsigned char *buf, size_t len)
{
    unsigned int h = 5381;
    for (size_t i = 0; i < len; ++i)
        h = ((h << 5) + h) + buf[i];
    return h % CACHE_BUCKETS;
}

/* ------------------------------------------------------------
 * Initialize cache
 * ------------------------------------------------------------ */
void cache_init(void)
{
    memset(table, 0, sizeof(table));
    cache_hits = 0;
    cache_misses = 0;
}

/* Extract TTL from DNS response (simplified) */
static unsigned int extract_ttl(const unsigned char *reply, size_t reply_len)
{
    /* Default TTL if we can't parse */
    unsigned int default_ttl = 300;  /* 5 minutes */

    if (reply_len < 12)
        return default_ttl;

    /* This is a simplified extraction – real DNS parsing is complex */
    /* For now, use a default TTL */
    return default_ttl;
}

/* ------------------------------------------------------------
 * Insert entry into cache with TTL
 * ------------------------------------------------------------ */
void cache_insert(const unsigned char *key,
                  size_t key_len,
                  const unsigned char *reply,
                  size_t reply_len,
                  unsigned int ttl)
{
    unsigned int bucket = hash_buf(key, key_len);

    CacheEntry *entry = malloc(sizeof(CacheEntry));
    if (!entry) return;

    entry->key = malloc(key_len);
    if (!entry->key) {
        free(entry);
        return;
    }
    memcpy(entry->key, key, key_len);
    entry->key_len = key_len;

    entry->reply = malloc(reply_len);
    if (!entry->reply) {
        free(entry->key);
        free(entry);
        return;
    }
    memcpy(entry->reply, reply, reply_len);
    entry->reply_len = reply_len;

    /* Set expiry time */
    entry->expiry = time(NULL) + ttl;

    /* Insert at head of bucket */
    entry->next = table[bucket];
    table[bucket] = entry;
}

/* ------------------------------------------------------------
 * Look up cache entry (returns NULL if not found or expired)
 * ------------------------------------------------------------ */
const CacheEntry *cache_lookup(const unsigned char *key, size_t key_len)
{
    unsigned int bucket = hash_buf(key, key_len);
    time_t now = time(NULL);

    for (CacheEntry *e = table[bucket]; e != NULL; e = e->next) {
        if (e->key_len == key_len && memcmp(e->key, key, key_len) == 0) {
            /* Check if expired */
            if (now > e->expiry) {
                cache_misses++;
                return NULL;  /* expired */
            }
            cache_hits++;
            return e;
        }
    }

    cache_misses++;
    return NULL;
}

/* ------------------------------------------------------------
 * Dump cache contents (for debugging)
 * ------------------------------------------------------------ */
void cache_dump(void)
{
    time_t now = time(NULL);
    printf("=== Cache Contents ===\n");
    printf("Hits: %lu, Misses: %lu\n", cache_hits, cache_misses);

    int total = 0;
    for (int i = 0; i < CACHE_BUCKETS; ++i) {
        for (CacheEntry *e = table[i]; e != NULL; e = e->next) {
            int remaining = (int)(e->expiry - now);
            printf("Entry [bucket %d]: key_len=%zu, reply_len=%zu, expires in %d sec\n",
                   i, e->key_len, e->reply_len, remaining);
            total++;
        }
    }
    printf("Total entries: %d\n", total);
}

/* ------------------------------------------------------------
 * Save cache to file (with expiry times)
 * ------------------------------------------------------------ */
void cache_save(FILE *f)
{
    time_t now = time(NULL);

    for (int i = 0; i < CACHE_BUCKETS; ++i) {
        for (CacheEntry *e = table[i]; e != NULL; e = e->next) {
            /* Only save non-expired entries */
            if (now <= e->expiry) {
                unsigned int remaining_ttl = (unsigned int)(e->expiry - now);
                fwrite(&e->key_len, sizeof(e->key_len), 1, f);
                fwrite(e->key, e->key_len, 1, f);
                fwrite(&e->reply_len, sizeof(e->reply_len), 1, f);
                fwrite(e->reply, e->reply_len, 1, f);
                fwrite(&remaining_ttl, sizeof(remaining_ttl), 1, f);
            }
        }
    }
}

/* ------------------------------------------------------------
 * Destroy cache and free all memory
 * ------------------------------------------------------------ */
void cache_destroy(void)
{
    for (int i = 0; i < CACHE_BUCKETS; ++i) {
        CacheEntry *e = table[i];
        while (e) {
            CacheEntry *next = e->next;
            free(e->key);
            free(e->reply);
            free(e);
            e = next;
        }
        table[i] = NULL;
    }
    printf("Cache destroyed. Final stats – Hits: %lu, Misses: %lu\n",
           cache_hits, cache_misses);
}

/* Get current cache size */
size_t cache_size(void)
{
    size_t count = 0;
    for (int i = 0; i < CACHE_BUCKETS; ++i) {
        for (CacheEntry *e = table[i]; e != NULL; e = e->next)
            count++;
    }
    return count;
}

#ifndef CACHE_H
#define CACHE_H

#include <stddef.h>
#include <stdio.h>
#include <time.h>

/* Opaque cache entry – callers only read the fields. */
typedef struct CacheEntry {
    unsigned char *key;
    size_t key_len;
    unsigned char *reply;
    size_t reply_len;
    time_t expiry;          /* when this entry expires */
    struct CacheEntry *next;
} CacheEntry;

/* Initialise the cache.  Must be called before any other cache_* call. */
void cache_init(void);

/* Insert a new key/value pair with TTL.  The function copies the reply data. */
void cache_insert(const unsigned char *key,
                  size_t key_len,
                  const unsigned char *reply,
                  size_t reply_len,
                  unsigned int ttl);

/* Look up the cached reply for the given key.  Returns NULL if not found or expired. */
const CacheEntry *cache_lookup(const unsigned char *key,
                               size_t key_len);

/* Dump the contents of the cache to stdout (debug helper). */
void cache_dump(void);

/* Save cache entries to file */
void cache_save(FILE *f);

/* Destroy and cleanup cache */
void cache_destroy(void);

/* Get current cache size (number of entries) */
size_t cache_size(void);

#endif /* CACHE_H */

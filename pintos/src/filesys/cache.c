#include <debug.h>
#include <string.h>
#include <stdio.h>
#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "devices/timer.h"
#include "threads/thread.h"
#include "threads/synch.h"


#if (DEBUG & DEBUG_CACHE)
#define DEBUG_WRITE_BEHIND       0
#else
#define DEBUG_WRITE_BEHIND       0
#endif

#if DEBUG_WRITE_BEHIND
#define PRINT_WRITE_BEHIND(X) {printf("(write-behind) "); printf(X);}
#define PRINT_WRITE_BEHIND_2(X,Y) {printf("(write-behind) "); printf(X,Y);}
#else
#define PRINT_WRITE_BEHIND(X) do {} while(0)
#define PRINT_WRITE_BEHIND_2(X,Y) do {} while(0)
#endif

#define CACHE_LEN 50

#define CACHE_WAIT_TIME 10

struct cache_sector
{
	char data[BLOCK_SECTOR_SIZE];
};

/*
enum sector_type 
{
	stype_data,
	stype_meta,

};
*/

struct cache_entry
{
	struct hash_elem h_elem;
	struct list_elem l_elem;
	block_sector_t sector_idx;
	int slot; /* cache slot */
	bool dirty;
};

static struct hash cache_hash;
static struct cache_sector cache_array[CACHE_LEN];
static struct list list_data;
static struct lock lock_map;
/*static struct list list_meta;*/


void cache_flush_entry(struct cache_entry *ce);

struct cache_entry *cache_put(block_sector_t sector_idx, bool meta UNUSED);
void cache_set_dirty(struct cache_entry *ce, bool value);
void cache_update_lru(struct cache_entry *ce, bool meta UNUSED);

int cache_evict(void);
struct cache_entry *cache_insert(block_sector_t sector_idx, int slot);	
struct cache_entry *cache_get_entry(block_sector_t sector_idx);
bool cache_cmp(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
unsigned cache_hash_func(const struct hash_elem *e, void *aux UNUSED);
void hash_clean_entry(struct hash_elem *he, void *aux UNUSED);
void cache_write_behind_loop(void *_cache_wait);


/* intialize the cache structures */
void
cache_init(void)
{
	hash_init(&cache_hash, &cache_hash_func, &cache_cmp, NULL);	/* hash table for fast lookup	*/
	list_init(&list_data);	/* list of cached data sectors */
	/*list_init(&list_meta);*/	/* list of cached meta-data sectors	*/
	lock_init(&lock_map);
	thread_create ("flusher", 0, &cache_write_behind_loop, (void *)CACHE_WAIT_TIME); 
}

void
cache_write_behind_loop(void *_cache_wait){
	int cache_wait = (int)_cache_wait;
	PRINT_WRITE_BEHIND_2("cache wait is :%d", cache_wait);
	while(true){

		timer_msleep(cache_wait);
		PRINT_WRITE_BEHIND("I am about to flush the cache!\n");
		lock_acquire(&lock_map);
		cache_flush();
		lock_release(&lock_map);
	}
}

/* flush the dirty sectors in cache to disk */
void
cache_flush(void)
{
	hash_apply (&cache_hash, &hash_clean_entry);
}

void
cache_flush_entry(struct cache_entry *ce)
{
	block_write (fs_device, ce->sector_idx, &(cache_array[ce->slot]));
}

/* returns the new cache_entry struct for SECTOR */
struct cache_entry * 
cache_put(block_sector_t sector_idx, bool meta UNUSED)
{
	struct cache_entry *ce = cache_get_entry(sector_idx);
	if (ce == NULL)
	{
		int slot;
		int slots_used = hash_size(&cache_hash);
		if (slots_used < CACHE_LEN)
			slot = slots_used;
		else {
			slot = cache_evict();
		}
		ce = cache_insert(sector_idx, slot);	
	}
	else
	ASSERT(ce != NULL);
	return ce;
}

void
cache_set_dirty(struct cache_entry *ce, bool value)
{
	ce->dirty = value;
}

/* move the cached SECTOR to the back of lru queue */
void 
cache_update_lru(struct cache_entry *ce, bool meta UNUSED)
{
	list_remove(&ce->l_elem);
	list_push_back(&list_data, &ce->l_elem);
	/*
	if (meta) {
		list_push_back(&list_meta, ce->l_elem);
	} else {
		list_push_back(&list_data, ce->l_elem);
	}
	*/
}

/* evict a cache sector and return the index
   of the available slot */
int
cache_evict(void)
{
	struct list_elem *e = list_pop_front(&list_data);
	struct cache_entry *ce = list_entry(e, struct cache_entry, l_elem);
	int slot = ce->slot;

	if (ce->dirty)
		cache_flush_entry(ce);
	
	struct hash_elem *old = hash_delete (&cache_hash, &ce->h_elem);
	ASSERT(old != NULL);
	free(ce);

	return slot;
}

struct cache_entry *
cache_insert(block_sector_t sector_idx, int slot)
{
	struct cache_entry *ce = malloc(sizeof(struct cache_entry));
	ASSERT(ce != NULL);

	ce->sector_idx = sector_idx;
	ce->slot = slot;
	ce->dirty = false;

	struct hash_elem *old = hash_insert (&cache_hash, &ce->h_elem);

	/* load the actual data here. now. */
	block_read (fs_device, ce->sector_idx, &(cache_array[ce->slot]));

	ASSERT(old == NULL);
	list_push_back(&list_data, &ce->l_elem);

	return ce;
}


void 
cache_read (block_sector_t sector_idx, void *buffer, 
								 int sector_ofs, int chunk_size, bool meta)
{
	lock_acquire(&lock_map);
		
	struct cache_entry *ce = cache_put(sector_idx, meta);
	ASSERT(ce->slot >= 0 && ce->slot < CACHE_LEN);
	ASSERT(sector_ofs + chunk_size <= BLOCK_SECTOR_SIZE);
	memcpy (buffer, cache_array[ce->slot].data + sector_ofs, chunk_size);
	cache_update_lru(ce, meta);

	lock_release(&lock_map);
}

void 
cache_write (block_sector_t sector_idx, const void *buffer, 
								 int sector_ofs, int chunk_size, bool meta)
{
	lock_acquire(&lock_map);

	struct cache_entry *ce = cache_put(sector_idx, meta);
	ASSERT(ce->slot >= 0 && ce->slot < CACHE_LEN);
	ASSERT(sector_ofs + chunk_size <= BLOCK_SECTOR_SIZE);
	memcpy (cache_array[ce->slot].data + sector_ofs, buffer, chunk_size);
	cache_set_dirty(ce, true);
	cache_update_lru(ce, meta);

	lock_release(&lock_map);
}


/* hash helper functions */
struct cache_entry *
cache_get_entry(block_sector_t sector_idx)
{
	struct cache_entry temp;
	temp.sector_idx = sector_idx;
	
	struct hash_elem *he = hash_find(&cache_hash, &(temp.h_elem));
	
	if (he == NULL)
	  return NULL;
	
	return hash_entry(he, struct cache_entry, h_elem);
}


bool 
cache_cmp(const struct hash_elem *a,
         const struct hash_elem *b,
         void *aux UNUSED)
{
	struct cache_entry *ce_a = hash_entry(a, struct cache_entry, h_elem);
	struct cache_entry *ce_b = hash_entry(b, struct cache_entry, h_elem);
	return ce_a->sector_idx < ce_b->sector_idx;
}

unsigned 
cache_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
	struct cache_entry *ce = hash_entry(e, struct cache_entry, h_elem);
	return hash_int((int) ce->sector_idx);
}

void hash_clean_entry(struct hash_elem *he, void *aux UNUSED)
{
	struct cache_entry *ce = hash_entry(he, struct cache_entry, h_elem);
	if (ce->dirty)	{
		cache_flush_entry(ce);
		cache_set_dirty(ce, false);
	}	
}



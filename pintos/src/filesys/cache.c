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
#define DEBUG_CINIT							 1
#else
#define DEBUG_WRITE_BEHIND       0
#define DEBUG_CINIT							 0
#endif

#if DEBUG_WRITE_BEHIND
#define PRINT_WRITE_BEHIND(X) {printf("(write-behind) "); printf(X);}
#define PRINT_WRITE_BEHIND_2(X,Y) {printf("(write-behind) "); printf(X,Y);}
#else
#define PRINT_WRITE_BEHIND(X) do {} while(0)
#define PRINT_WRITE_BEHIND_2(X,Y) do {} while(0)
#endif

#if DEBUG_CINIT
#define PRINT_CINIT(X) {printf("(cache-init) "); printf(X);}
#define PRINT_CINIT_2(X,Y) {printf("(cache-init) "); printf(X,Y);}
#else
#define PRINT_CINIT(X) do {} while(0)
#define PRINT_CINIT_2(X,Y) do {} while(0)
#endif

#define CACHE_SIZE 50

#define CACHE_WAIT_TIME 10

struct cache_slot
{
	char data[BLOCK_SECTOR_SIZE];
	/* synchronization */
	int num_accessors;
	bool pending_io;
	bool io_busy;
	struct condition cond;
	bool dirty;
	block_sector_t sector;
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
};

static struct hash cache_hash;
static struct cache_slot cache_array[CACHE_SIZE];
static struct list list_data;
/*static struct list list_meta;*/

static struct lock lock_map;



/* intialize the cache structures */
void cache_write_behind_loop(void *_cache_wait);
void cache_flush_entry(struct cache_entry *ce);
struct cache_entry *cache_put(block_sector_t sector_idx, bool meta UNUSED);
struct cache_entry *cache_slot_init(int slot, block_sector_t sector_idx);
void cache_set_dirty(struct cache_slot *cs, bool value);
void cache_lru_remove(struct cache_entry *ce, bool meta UNUSED);
void cache_lru_insert(struct cache_entry *ce, bool meta UNUSED);
int cache_evict(void);
struct cache_entry *cache_get_entry(block_sector_t sector_idx);
struct cache_slot* cache_get_slot(struct cache_entry *ce);
bool cache_cmp(const struct hash_elem *a,const struct hash_elem *b,void *aux UNUSED);
unsigned cache_hash_func(const struct hash_elem *e, void *aux UNUSED);
void hash_clean_entry(struct hash_elem *he, void *aux UNUSED);



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
	struct cache_slot *cs = cache_get_slot(ce);
	block_write (fs_device, ce->sector_idx, &cs->data);
}

/* returns the new cache_entry struct for SECTOR */
struct cache_entry* 
cache_put(block_sector_t sector_idx, bool meta UNUSED)
{
	ASSERT(lock_held_by_current_thread(&lock_map));
	static int next_slot = 0;

	struct cache_entry *ce = cache_get_entry(sector_idx);
	if (ce == NULL)
	{
		int slot;
		if (next_slot < CACHE_SIZE) {
			slot = next_slot;
			next_slot++;
		} else {
			slot = cache_evict();
		}
		ce = cache_slot_init(slot, sector_idx);	
	}
	
	return ce;
}

/* evict a cache sector and return the index
   of the available slot */
int
cache_evict(void)
{
	ASSERT(lock_held_by_current_thread(&lock_map));

	struct list_elem *e = list_pop_front(&list_data);
	struct cache_entry *ce = list_entry(e, struct cache_entry, l_elem);
	struct cache_slot * cs = cache_get_slot(ce);

	if (cs->dirty)
		cache_flush_entry(ce);
	
	struct hash_elem *old = hash_delete (&cache_hash, &ce->h_elem);
	ASSERT(old != NULL);
	int slot = ce->slot;
	free(ce);

	return slot;
}	


struct cache_entry *
cache_slot_init(int slot, block_sector_t sector_idx)
{
	struct cache_entry *ce = malloc(sizeof(struct cache_entry));
	if (ce == NULL)
		PANIC("could not allocate cache entry");

	PRINT_CINIT_2("sector_idx: %d\n",sector_idx);
	PRINT_CINIT_2("slot: %d\n",slot);

	ce->sector_idx = sector_idx;
	ce->slot = slot;

	struct cache_slot *cs = &cache_array[slot];
	cs->dirty = false;
	cs->num_accessors = 0;
	cs->pending_io = false;
	cs->io_busy = false;
	cs->sector = sector_idx;
	cond_init(&cs->cond);

	struct hash_elem *old = hash_insert (&cache_hash, &ce->h_elem);

	/* load the actual data here. now. */
	block_read (fs_device, sector_idx, &cs->data);

	ASSERT(old == NULL);
	list_push_back(&list_data, &ce->l_elem);

	return ce;
}





void
cache_set_dirty(struct cache_slot *cs, bool value)
{
	cs->dirty = value;
}

/* move the cached SECTOR to the back of lru queue */
void 
cache_lru_remove(struct cache_entry *ce, bool meta UNUSED)
{
	list_remove(&ce->l_elem);
	/*
	if (meta) {
		list_push_back(&list_meta, ce->l_elem);
	} else {
		list_push_back(&list_data, ce->l_elem);
	}
	*/
}

void
cache_lru_insert(struct cache_entry *ce, bool meta UNUSED)
{
	list_push_back(&list_data, &ce->l_elem);
}


void 
cache_read (block_sector_t sector_idx, void *buffer, 
								 int sector_ofs, int chunk_size, bool meta)
{
	lock_acquire(&lock_map);	
	struct cache_slot *cs;
	struct cache_entry *ce;
	while (true) {
		ce = cache_put(sector_idx, meta);
		cs = cache_get_slot(ce);
		if (!cs->io_busy)
			break;
		cond_wait(&cs->cond,&lock_map);
	}
	cs->num_accessors++;
	cache_lru_remove(ce, meta);	
	cache_lru_insert(ce, meta);
	lock_release(&lock_map);

	/*ASSERT(ce->slot >= 0 && cs->slot < CACHE_LEN);*/
	ASSERT(sector_ofs + chunk_size <= BLOCK_SECTOR_SIZE);
	memcpy (buffer, cs->data + sector_ofs, chunk_size);

	lock_acquire(&lock_map);
	cs->num_accessors--;
	lock_release(&lock_map);

}

void 
cache_write (block_sector_t sector_idx, const void *buffer, 
								 int sector_ofs, int chunk_size, bool meta)
{
	lock_acquire(&lock_map);	
	struct cache_slot *cs;
	struct cache_entry *ce;
	while (true) {
		ce = cache_put(sector_idx, meta);
		cs = cache_get_slot(ce);
		if (!cs->io_busy)
			break;
		cond_wait(&cs->cond,&lock_map);
	}
	cs->num_accessors++;
	cache_lru_remove(ce, meta);	
	cache_lru_insert(ce, meta);
	lock_release(&lock_map);


	/*ASSERT(ce->slot >= 0 && ce->slot < CACHE_LEN);*/
	ASSERT(sector_ofs + chunk_size <= BLOCK_SECTOR_SIZE);
	memcpy (cs->data + sector_ofs, buffer, chunk_size);
	cache_set_dirty(cs, true);

	lock_acquire(&lock_map);
	cs->num_accessors--;
	lock_release(&lock_map);
}

struct cache_slot* 
cache_get_slot(struct cache_entry *ce)
{
	return &cache_array[ce->slot];
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
	struct cache_slot *cs = &cache_array[ce->slot];
	if (cs->dirty)	{
		cache_flush_entry(ce);
		cache_set_dirty(cs, false);
	}	
}



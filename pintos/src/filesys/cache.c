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
#define DEBUG_CINIT							 0
#define DEBUG_CPUT							 1
#define DEBUG_CFLUSH						 0
#else
#define DEBUG_WRITE_BEHIND       0
#define DEBUG_CINIT							 0
#define DEBUG_CPUT							 0
#define DEBUG_CFLUSH						 0
#endif

#if DEBUG_WRITE_BEHIND
#define PRINT_WRITE_BEHIND(X) {printf("(write-behind) "); printf(X);}
#define PRINT_WRITE_BEHIND_2(X,Y) {printf("(write-behind) "); printf(X,Y);}
#else
#define PRINT_WRITE_BEHIND(X) do {} while(0)
#define PRINT_WRITE_BEHIND_2(X,Y) do {} while(0)
#endif

#if DEBUG_CPUT
#define PRINT_CPUT(X) {printf("(cache-put) "); printf(X);}
#define PRINT_CPUT_2(X,Y) {printf("(cache-put) "); printf(X,Y);}
/*void print_cache() 
{
	for (int i=0; i<CACHE_SIZE; i++) 
	{
		p
	}
}*/
#else
#define PRINT_CPUT(X) do {} while(0)
#define PRINT_CPUT_2(X,Y) do {} while(0)
#endif

#if DEBUG_CINIT
#define PRINT_CINIT(X) {printf("(cache-slot-init) "); printf(X);}
#define PRINT_CINIT_2(X,Y) {printf("(cache-slot-init) "); printf(X,Y);}
#else
#define PRINT_CINIT(X) do {} while(0)
#define PRINT_CINIT_2(X,Y) do {} while(0)
#endif

#if DEBUG_CFLUSH
#define PRINT_CFLUSH(X) {printf("(cache-flush) "); printf(X);}
#define PRINT_CFLUSH_2(X,Y) {printf("(cache-flush) "); printf(X,Y);}
#else
#define PRINT_CFLUSH(X) do {} while(0)
#define PRINT_CFLUSH_2(X,Y) do {} while(0)
#endif



#define CACHE_SIZE 50

#define CACHE_WAIT_TIME 10

struct cache_slot
{
	char data[BLOCK_SECTOR_SIZE];
	/* synchronization */
	int num_accessors;
	bool pending_evict;
	bool io_busy;
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
	struct condition evictable;
	struct condition readable;
	block_sector_t sector;
	int slot; /* cache slot */
};

static struct hash cache_hash;
static struct cache_slot cache_array[CACHE_SIZE];
static struct list list_data;
/*static struct list list_meta;*/

static struct lock lock_map;



/* intialize the cache structures */
void cache_write_behind_loop(void *_cache_wait);
void cache_flush_entry(struct cache_slot *cs);
struct cache_entry *cache_put(block_sector_t sector, bool meta UNUSED);
void cache_slot_init(struct cache_slot *cs,block_sector_t sector);
void cache_set_dirty(struct cache_slot *cs, bool value);
void cache_lru_remove(struct cache_entry *ce, bool meta UNUSED);
void cache_lru_insert(struct cache_entry *ce, bool meta UNUSED);
void cache_evict(struct cache_entry *new_ce);
struct cache_entry *cache_get_entry(block_sector_t sector);
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
		/*cache_flush();*/
	}
}

/* flush the dirty sectors in cache to disk */
void
cache_flush(void)
{
	/*hash_apply (&cache_hash, &hash_clean_entry);*/
	int i=0;
	for (i=0;i<CACHE_SIZE;i++) {
		PRINT_CFLUSH_2("flushing slot: %d\n",i);
		cache_flush_entry(&cache_array[i]);
	}
}

void
cache_flush_entry(struct cache_slot *cs)
{
	PRINT_CFLUSH_2("cs->dirty: %d\n",cs->dirty);
	PRINT_CFLUSH_2("cs->pending_evict: %d\n", cs->pending_evict);
	PRINT_CFLUSH_2("cs->io_busy: %d\n", cs->io_busy);
	PRINT_CFLUSH_2("cs->data: %s\n", cs->data);
	lock_acquire(&lock_map);
	if (!cs->dirty || cs->pending_evict || cs->io_busy) {
		lock_release(&lock_map);
		return;
	}
	cs->io_busy = true;
	lock_release(&lock_map);
	block_write (fs_device, cs->sector, &cs->data);
	lock_acquire(&lock_map);
	cs->io_busy = false;
	lock_release(&lock_map);
}

/* returns the new cache_entry struct for SECTOR */
struct cache_entry* 
cache_put(block_sector_t sector, bool meta UNUSED)
{
	ASSERT(lock_held_by_current_thread(&lock_map));
	static int next_slot = 0;

	struct cache_entry *ce = cache_get_entry(sector);
	if (ce == NULL)
	{
		
		ce = malloc(sizeof(struct cache_entry));
		cond_init(&ce->readable);
		cond_init(&ce->evictable);
		if (ce == NULL)
			PANIC("could not allocate cache entry");
		ce->sector = sector;
		hash_insert (&cache_hash, &ce->h_elem);

		PRINT_CPUT_2("slots used: %d\n", next_slot);
		if (next_slot < CACHE_SIZE) {
			ce->slot = next_slot;
			next_slot++;
		} else {
			cache_evict(ce);
			struct cache_slot *cs = cache_get_slot(ce);
			cs->io_busy = true;
			lock_release(&lock_map);
			block_read (fs_device, sector, &cs->data);
			/* assuming noone will evict or read if io_busy set to true */
			lock_acquire(&lock_map);
			cs->io_busy = false;
			ASSERT(!cs->pending_evict);
			cond_broadcast(&ce->readable,&lock_map);
		}
		cache_slot_init(cache_get_slot(ce),ce->sector);
		list_push_back(&list_data, &ce->l_elem);

	}
	
	return ce;
}

/* evict a cache sector and return the index
   of the available slot */
void
cache_evict(struct cache_entry *new_ce)
{
	ASSERT(lock_held_by_current_thread(&lock_map));

	struct list_elem *e = list_pop_front(&list_data);
	struct cache_entry *old_ce = list_entry(e, struct cache_entry, l_elem);
	struct cache_slot * cs = cache_get_slot(old_ce);

	ASSERT(!cs->pending_evict);
	ASSERT(!cs->io_busy);

	new_ce->slot = old_ce->slot;

	while (cs->num_accessors > 0) {
		cs->pending_evict = true;
		cond_wait(&old_ce->evictable,&lock_map);
	}
	cs->pending_evict = false;

	if (cs->dirty) {
		cs->io_busy = true;
		lock_release(&lock_map);
		cache_flush_entry(cs); 
		/* assuming noone will evict or read if io_busy set to true */
		lock_acquire(&lock_map);
		cs->io_busy = false;
	}

	struct hash_elem *old = hash_delete (&cache_hash, &old_ce->h_elem);
	ASSERT(old != NULL);
	cond_signal(&old_ce->readable,&lock_map);
	free(old_ce);
}	


void
cache_slot_init(struct cache_slot *cs, block_sector_t sector)
{
	PRINT_CINIT_2("sector: %d\n",sector);
	PRINT_CINIT_2("slot: %p\n",cs);

	cs->dirty = false;
	cs->num_accessors = 0;
	cs->pending_evict = false;
	cs->io_busy = false;
	cs->sector = sector;	
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
cache_read (block_sector_t sector, void *buffer, 
								 int sector_ofs, int chunk_size, bool meta)
{
	lock_acquire(&lock_map);	
	struct cache_slot *cs;
	struct cache_entry *ce;
	while (true) {
		ce = cache_put(sector, meta);
		cs = cache_get_slot(ce);
		if (!cs->io_busy && !cs->pending_evict)
			break;
		cond_wait(&ce->readable,&lock_map);
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
	if (cs->pending_evict && cs->num_accessors == 0)
			cond_signal(&ce->evictable,&lock_map);

	lock_release(&lock_map);

}

void 
cache_write (block_sector_t sector, const void *buffer, 
								 int sector_ofs, int chunk_size, bool meta)
{
	lock_acquire(&lock_map);	
	struct cache_slot *cs;
	struct cache_entry *ce;
	while (true) {
		ce = cache_put(sector, meta);
		cs = cache_get_slot(ce);
		if (!cs->io_busy && !cs->pending_evict)
			break;
		cond_wait(&ce->readable,&lock_map);
	}
	cs->num_accessors++;
	cache_lru_remove(ce, meta);	
	cache_lru_insert(ce, meta);
	lock_release(&lock_map);


	/*ASSERT(ce->slot >= 0 && ce->slot < CACHE_LEN);*/
	ASSERT(sector_ofs + chunk_size <= BLOCK_SECTOR_SIZE);
	memcpy (cs->data + sector_ofs, buffer, chunk_size);

	lock_acquire(&lock_map);
	cs->num_accessors--;
	cache_set_dirty(cs, true);
	if (cs->pending_evict && cs->num_accessors == 0)
			cond_signal(&ce->evictable,&lock_map);
	lock_release(&lock_map);
}

struct cache_slot* 
cache_get_slot(struct cache_entry *ce)
{
	return &cache_array[ce->slot];
}

/* hash helper functions */

struct cache_entry *
cache_get_entry(block_sector_t sector)
{
	struct cache_entry temp;
	temp.sector = sector;
	
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
	return ce_a->sector < ce_b->sector;
}

unsigned 
cache_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
	struct cache_entry *ce = hash_entry(e, struct cache_entry, h_elem);
	return hash_int((int) ce->sector);
}

void hash_clean_entry(struct hash_elem *he, void *aux UNUSED)
{
	struct cache_entry *ce = hash_entry(he, struct cache_entry, h_elem);
	struct cache_slot *cs = &cache_array[ce->slot];
	if (cs->dirty)	{
		cache_flush_entry(cs);
		cache_set_dirty(cs, false);
	}	
}



#include <debug.h>
#include <string.h>
#include <stdio.h>
#include <list.h>
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
#define DEBUG_CFETCH						 1
#define DEBUG_CFETCH_LOOP				 1
#else
#define DEBUG_WRITE_BEHIND       0
#define DEBUG_CINIT							 0
#define DEBUG_CPUT							 0
#define DEBUG_CFETCH 						 0
#define DEBUG_CFETCH_LOOP				 0
#endif

#if DEBUG_CFETCH_LOOP
#define PRINT_CFETCH_LOOP(X) {printf("(cache-fetch-loop) "); printf(X);}
#define PRINT_CFETCH_LOOP_2(X,Y) {printf("(cache-fetch-loop) "); printf(X,Y);}
#else
#define PRINT_CFETCH_LOOP(X) do {} while(0)
#define PRINT_CFETCH_LOOP_2(X,Y) do {} while(0)
#endif

#if DEBUG_CFETCH
#define PRINT_CFETCH(X) {printf("(cache-fetch) "); printf(X);}
#define PRINT_CFETCH_2(X,Y) {printf("(cache-fetch) "); printf(X,Y);}
#else
#define PRINT_CFETCH(X) do {} while(0)
#define PRINT_CFETCH_2(X,Y) do {} while(0)
#endif

#if DEBUG_CPUT
#define PRINT_CPUT(X) {printf("(cache-put) "); printf(X);}
#define PRINT_CPUT_2(X,Y) {printf("(cache-put) "); printf(X,Y);}
#else
#define PRINT_CPUT(X) do {} while(0)
#define PRINT_CPUT_2(X,Y) do {} while(0)
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
	bool pending_evict;
	bool io_busy;
	struct condition io_done;
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
	block_sector_t sector;
	int slot; /* cache slot */
};

static struct hash cache_hash;
static struct cache_slot cache_array[CACHE_SIZE];
static struct list list_data;
/*static struct list list_meta;*/

static struct lock lock_map;
static struct lock lock_fetch;
static struct condition cond_fetch;
/* static struct condition cond_temp;*/
static struct list qfetch;

struct fetch_request {
	block_sector_t sector;
	struct list_elem elem;
	bool meta;
};



/* intialize the cache structures */
void cache_write_behind_loop(void *_cache_wait);
void cache_fetch_loop(void *aux UNUSED);
void cache_fetch(block_sector_t sector,bool meta);
void cache_flush_entry(struct cache_slot *cs);
/*void cache_flush_entry(struct cache_entry *ce);*/
struct cache_entry *cache_put(block_sector_t sector, bool meta UNUSED);
void cache_slot_init(struct cache_entry *ce);
void cache_set_dirty(struct cache_slot *cs, bool value);
void cache_lru_remove(struct cache_entry *ce, bool meta UNUSED);
void cache_lru_insert(struct cache_entry *ce, bool meta UNUSED);
void cache_evict(struct cache_entry *ce);
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

	lock_init(&lock_fetch);
	cond_init(&cond_fetch);
	/*cond_init(&cond_temp);*/
	list_init(&qfetch);

	int i;
	for (i=0;i<CACHE_SIZE;i++) {
		struct cache_slot *cs = &cache_array[i];
		cs->num_accessors = 0;
		cs->pending_evict = false;
		cs->io_busy = false;
		cond_init(&cs->io_done);
		cs->dirty = false;
		cs->sector = 0;
	}

	thread_create ("flusher", 0, &cache_write_behind_loop, (void *)CACHE_WAIT_TIME); 
	thread_create ("fetcher", 0, &cache_fetch_loop, NULL);

}

void cache_fetch(block_sector_t sector, bool meta)
{
	struct fetch_request *freq = malloc(sizeof(struct fetch_request));
	if (!freq)
		PANIC("can't allocate fetch request");
	freq->sector = sector;
	freq->meta = meta;
	

	lock_acquire(&lock_fetch);
	PRINT_CFETCH_2("freq: %p\n",freq);
	PRINT_CFETCH_2("sector: %d\n",sector);

	/*while (!list_empty(&qfetch))
		cond_wait(&cond_temp,&lock_fetch);*/

	list_push_back(&qfetch,&freq->elem);
	cond_signal(&cond_fetch,&lock_fetch);
	lock_release(&lock_fetch);
	PRINT_CFETCH("finishing...\n");
}

void 
cache_fetch_loop(void *aux UNUSED)
{
	while (true)
	{
		lock_acquire(&lock_fetch);
		PRINT_CFETCH_LOOP("milestone 1\n");
		PRINT_CFETCH_LOOP("milestone 2: acquired lock_fetch.\n");
		while (list_empty(&qfetch)) {
			PRINT_CFETCH_LOOP("milestone 3: qfetch empty, waiting...\n");
			cond_wait(&cond_fetch,&lock_fetch);
		}

		PRINT_CFETCH_LOOP("milestone 4: new fetch request!\n");
		struct fetch_request *freq = list_entry(list_pop_front(&qfetch),struct fetch_request, elem);
		PRINT_CFETCH_LOOP_2("freq: %p\n",freq);
		PRINT_CFETCH_LOOP_2("sector: %d\n",freq->sector);
		lock_release(&lock_fetch);

		ASSERT(freq != NULL);
		lock_acquire(&lock_map);
		PRINT_CFETCH_LOOP("milestone 5: calling cache_put...\n");
		cache_put(freq->sector,freq->meta);
		PRINT_CFETCH_LOOP_2("milestone 6: cache_put returned. %d\n",freq->sector);
		/*cond_signal(&cond_temp,&lock_fetch);*/
		lock_release(&lock_map);
		free(freq);
	}
	NOT_REACHED();
}

void
cache_write_behind_loop(void *_cache_wait){
	int cache_wait = (int)_cache_wait;
	PRINT_WRITE_BEHIND_2("cache wait is :%d", cache_wait);
	while(true){

		timer_msleep(cache_wait);
		PRINT_WRITE_BEHIND("I am about to flush the cache!\n");
		cache_flush();
	}
}


void
cache_flush(void)
{
	int i;
	for (i=0;i<CACHE_SIZE;i++) {
		cache_flush_entry(&cache_array[i]);
	}
}


void
cache_flush_entry(struct cache_slot *cs)
{
	lock_acquire(&lock_map);
	while (cs->io_busy || cs->num_accessors > 0) {
			cond_wait(&cs->io_done,&lock_map);
	}

	cs->io_busy = true;
	lock_release(&lock_map);
	block_write (fs_device, cs->sector, &cs->data);
	lock_acquire(&lock_map);
	cs->io_busy = false;
	cs->dirty = false;
	cond_signal(&cs->io_done,&lock_map);
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
		if (ce == NULL)
			PANIC("could not allocate cache entry");
		ce->sector = sector;
		hash_insert (&cache_hash, &ce->h_elem);

		struct cache_slot *cs;
		if (next_slot < CACHE_SIZE) {
			ce->slot = next_slot;
			cs = &cache_array[ce->slot];
			cs->sector = ce->sector;
			next_slot++;
		} else {
			cache_evict(ce);
			cs = cache_get_slot(ce);
			cs = &cache_array[ce->slot];
			cs->sector = ce->sector;
			cs->io_busy = true;
			
			lock_release(&lock_map);
			block_read (fs_device, sector, &cs->data);
			lock_acquire(&lock_map);
			cs->io_busy = false;
			ASSERT(!cs->pending_evict);
			cond_broadcast(&cs->io_done,&lock_map);
		}
		cache_slot_init(ce);	/*remove*/
			/* load the actual data */
		block_read (fs_device, ce->sector, &cs->data);
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

	new_ce->slot = old_ce->slot;

	while (cs->num_accessors > 0 || cs->io_busy) {
		cs->pending_evict = true;
		cond_wait(&cs->io_done,&lock_map);
	}
	cs->pending_evict = false;


	if (cs->dirty) {
		cs->io_busy = true;
		lock_release(&lock_map);
		block_write (fs_device, cs->sector, &cs->data);
		lock_acquire(&lock_map);
		cs->io_busy = false;
	}
	
	struct hash_elem *old_he = hash_delete (&cache_hash, &old_ce->h_elem);
	ASSERT(old_he != NULL);
	cond_signal(&cs->io_done,&lock_map);
	free(old_ce);

}	

void
cache_slot_init(struct cache_entry *ce)
{
	PRINT_CINIT_2("sector: %d\n",sector);
	PRINT_CINIT_2("slot: %d\n",slot);

	struct cache_slot *cs = &cache_array[ce->slot];
	cs->dirty = false;
	cs->num_accessors = 0;
	cs->pending_evict = false;
	cs->io_busy = false;
	cond_init(&cs->io_done);
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
cache_read (block_sector_t sector, block_sector_t next_sector, 
						void *buffer, int sector_ofs, int chunk_size, bool meta)
{
	lock_acquire(&lock_map);	
	struct cache_slot *cs;
	struct cache_entry *ce;
	while (true) {
		ce = cache_put(sector, meta);
		cs = cache_get_slot(ce);
		if (!cs->io_busy && !cs->pending_evict)
			break;
		cond_wait(&cs->io_done,&lock_map);
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
	ASSERT(!cs->io_busy);
	if (cs->num_accessors == 0)
		cond_signal(&cs->io_done,&lock_map);
	lock_release(&lock_map);
	if (next_sector != FETCH_NONE)
		cache_fetch(next_sector,meta);
}

void 
cache_write (block_sector_t sector, block_sector_t next_sector,
						 const void *buffer, int sector_ofs, int chunk_size, bool meta)
{
	lock_acquire(&lock_map);	
	struct cache_slot *cs;
	struct cache_entry *ce;
	while (true) {
		ce = cache_put(sector, meta);
		cs = cache_get_slot(ce);
		if (!cs->io_busy && !cs->pending_evict)
			break;
		cond_wait(&cs->io_done,&lock_map);
	}
	cs->num_accessors++;
	cache_lru_remove(ce, meta);	
	cache_lru_insert(ce, meta);
	lock_release(&lock_map);


	/*ASSERT(ce->slot >= 0 && ce->slot < CACHE_LEN);*/
	ASSERT(sector_ofs + chunk_size <= BLOCK_SECTOR_SIZE);
	memcpy (cs->data + sector_ofs, buffer, chunk_size);

	lock_acquire(&lock_map);
	cache_set_dirty(cs, true);
	cs->num_accessors--;
	ASSERT(!cs->io_busy);
	if (cs->num_accessors == 0)
			cond_signal(&cs->io_done,&lock_map);
	lock_release(&lock_map);
	if (next_sector != FETCH_NONE)
		cache_fetch(next_sector,meta);
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



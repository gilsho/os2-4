#include <debug.h>
#include <string.h>
#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "devices/block.h"
#include "threads/malloc.h"

#define CACHE_LEN 50

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
	block_sector_t sector_index;
	uint8_t cache_index;
	bool dirty;
};

static struct hash cache_hash;
static struct cache_sector cache_array[CACHE_LEN];
static struct list list_data;
/*static struct list list_meta;*/



void cache_init(void);
void cache_flush(void);
int cache_get_slot(block_sector_t sector, bool meta UNUSED);
void cache_update_lru(block_sector_t sector, bool meta UNUSED);

int cache_evict(void);
struct cache_entry *cache_insert(block_sector_t sector, int slot);	

void cache_read (block_sector_t sector, void *buffer, 
								 int sector_ofs, int chunk_size, bool meta);
void cache_write (block_sector_t sector, void *buffer, 
								 int sector_ofs, int chunk_size, bool meta);



struct cache_entry *cache_get_entry(block_sector_t sector);
bool cache_cmp(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
unsigned cache_hash_func(const struct hash_elem *e, void *aux UNUSED);



/* intialize the cache structures */
void
cache_init(void)
{
	hash_init(&cache_hash, &cache_hash_func, &cache_cmp, NULL);	/* hash table for fast lookup	*/
	list_init(&list_data);	/* list of cached data sectors */
	/*list_init(&list_meta);*/	/* list of cached meta-data sectors	*/
}



/* flush the dirty sectors in cache to disk */
void
cache_flush(void)
{

}

/* returns the cache slot index for SECTOR */
int 
cache_get_slot(block_sector_t sector, bool meta UNUSED)
{
	struct cache_entry *ce = cache_get_entry(sector);
	if (ce == NULL)
	{
		int slot = cache_evict();
		ce = cache_insert(sector, slot);	
	}
	ASSERT(ce != NULL);
	return ce->cache_index;
}

/* move the cached SECTOR to the back of lru queue */
void 
cache_update_lru(block_sector_t sector, bool meta UNUSED)
{
	struct cache_entry *ce = cache_get_entry(sector);
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

	int slot = ce->cache_index;
	
	struct hash_elem *old = hash_delete (&cache_hash, &ce->h_elem);
	ASSERT(old != NULL);
	free(ce);

	return slot;
}

struct cache_entry *
cache_insert(block_sector_t sector, int slot)
{
	struct cache_entry *ce = malloc(sizeof(struct cache_entry));
	ASSERT(ce != NULL);

	ce->sector_index = sector;
	ce->cache_index = slot;
	ce->dirty = false;

	struct hash_elem *old = hash_insert (&cache_hash, &ce->h_elem);
	ASSERT(old == NULL);
}


void 
cache_read (block_sector_t sector, void *buffer, 
								 int sector_ofs, int chunk_size, bool meta)
{
	int slot = cache_get_slot(sector, meta);
	ASSERT(slot >= 0 && slot < CACHE_LEN);
	ASSERT(sector_ofs + chunk_size <= BLOCK_SECTOR_SIZE);
	memcpy (buffer, cache_array[slot].data + sector_ofs, chunk_size);
	cache_update_lru(sector, meta);
}

void 
cache_write (block_sector_t sector, void *buffer, 
								 int sector_ofs, int chunk_size, bool meta)
{
	int slot = cache_get_slot(sector, meta);
	ASSERT(slot >= 0 && slot < CACHE_LEN);
	ASSERT(sector_ofs + chunk_size <= BLOCK_SECTOR_SIZE);
	memcpy (cache_array[slot].data + sector_ofs, buffer, chunk_size);
	cache_update_lru(sector, meta);
}


/* hash helper functions */
struct cache_entry *
cache_get_entry(block_sector_t sector)
{
	struct cache_entry temp;
	temp.sector_index = sector;
	
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
	return ce_a->sector_index < ce_b->sector_index;
}

unsigned 
cache_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
	struct cache_entry *ce = hash_entry(e, struct cache_entry, h_elem);
	return hash_int((int) ce->sector_index);
}




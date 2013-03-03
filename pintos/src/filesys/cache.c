#include "filesys/cache.h"
#include "devices/block.h"

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
static struct list list_meta;



void cache_init(void);
void cache_flush(void);
void cache_read (struct block *block, block_sector_t sector, void *buffer, 
								 int sector_ofs, int chunk_size);

bool cache_cmp(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
unsigned cache_hash(const struct hash_elem *e, void *aux UNUSED);



/* intialize the cache structures */
void
cache_init(void)
{
	hash_init(&cache_hash);	/* hash table for fast lookup	*/
	list_init(&list_data);	/* list of cached data sectors */
	list_init(&list_meta);	/* list of cached meta-data sectors	*/
}



/* flush the dirty sectors in cache to disk */
void
cache_flush(void)
{

}

/* returns the cache slot index for SECTOR */
int 
cache_get_slot(block_sector_t sector)
{
	/*
		check cache for sector (cache_get_slot)
			if HIT, return slot
			if MISS, insert & return slot

			insert:
				if free slot exists, return index
				else evict LRU, return index

			load the backing file data into the new slot
		*/
}


void 
cache_read (block_sector_t sector, void *buffer, 
								 int sector_ofs, int chunk_size, bool meta)
{
	int slot = cache_get_slot(sector);
	ASSERT(slot >= 0 && slot < CACHE_LEN);
	ASSERT(sector_ofs + chunk_size <= BLOCK_SECTOR_SIZE);
	memcpy (buffer, cache_array[slot]->data + sector_ofs, chunk_size);
	cache_update_lru(sector, meta);
}

void 
cache_write (block_sector_t sector, void *buffer, 
								 int sector_ofs, int chunk_size)
{
	int slot = cache_get_slot(sector);
	ASSERT(slot >= 0 && slot < CACHE_LEN);
	ASSERT(sector_ofs + chunk_size <= BLOCK_SECTOR_SIZE);
	memcpy (cache_array[slot]->data + sector_ofs, buffer, chunk_size);
	cache_update_lru(sector, meta);
}



/* hash helper functions */
bool 
cache_cmp(const struct hash_elem *a,
         const struct hash_elem *b,
         void *aux UNUSED)
{
	struct cache_entry *ce_a = hash_entry(a, struct cache_entry, elem);
	struct cache_entry *ce_b = hash_entry(b, struct cache_entry, elem);
	return ce_a->sector_index < ce_b->sector_index;
}

unsigned 
cache_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
	struct cache_entry *ce = hash_entry(e, struct cache_entry, elem);
	return hash_int((int) ce->sector_index);
}


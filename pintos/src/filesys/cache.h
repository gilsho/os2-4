#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include <stdbool.h>
#include <hash.h>
#include "filesys/off_t.h"
#include "devices/block.h"


void cache_init(void);
void cache_flush(void);
void cache_read (block_sector_t sector, block_sector_t next_sector,
								 void *buffer, int sector_ofs, int chunk_size, bool meta);
void cache_write (block_sector_t sector, block_sector_t next_sector,
								  const void *buffer, int sector_ofs, int chunk_size, bool meta);


#define FETCH_NONE -1


#endif /* filesys/cache.h */

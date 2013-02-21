#ifndef VM_MMAP_H
#define VM_MMAP_H

#include <hash.h>

typedef int mapid_t;
typedef struct hash mmap_table;

struct mmap_entry 
{
  mapid_t mid;
	void *upage;
	struct *file;
	int filesize;
	struct hash_elem elem;
};

bool
mmap_

#endif

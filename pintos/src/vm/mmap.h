#ifndef VM_MMAP_H
#define VM_MMAP_H

#include <hash.h>

typedef int mapid_t;
typedef struct hash mmap_table;

struct mmap_entry 
{
  mapid_t mid;						/* hash key */
	void *upage;						/* start page */
	struct file *file;			/* file handler */
	int filesize;						/* byte-size of file */
	struct hash_elem elem;	/* hash table element */
};

void mmap_init(mmap_table *mmt);
void mmap_install_file(mmap_table *mmt, mapid_t mid, void *upage, struct file *file, uint32_t file_len);
void mmap_uninstall_file(mmap_table *mmt, mapid_t mid);


#endif

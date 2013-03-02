#ifndef VM_VMAN_H
#define VM_VMAN_H

#include "filesys/off_t.h"
#include <stdbool.h>
#include "filesys/filesys.h"
#include <inttypes.h>

void vman_init(void);
bool vman_upages_unmapped(void *upage_head, int npages);
bool vman_map_segment (void *upage, struct file *file, off_t offset, 
											 int init_data_bytes, int uninit_data_bytes, 
											 bool writable);
bool vman_map_file(void *upage, struct file *file, uint32_t file_len);
void vman_unmap_file(void *upage, uint32_t file_len);
bool vman_grow_stack(void);
void vman_load_page(void *upage);
bool vman_unmap(void *upage,int npages);
void vman_pin_page(void *upage);
void vman_unpin_page(void *upage);
void vman_free_all_pages(void);

#endif /* vm/vman.h */







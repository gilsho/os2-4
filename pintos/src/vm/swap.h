#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <filesys/off_t.h>

void swap_init(void);
void swap_read_slot(size_t slot_idx, void *kpage);
size_t swap_write_slot(void *kpage);
void swap_release_slot(size_t slot_idx);

#endif

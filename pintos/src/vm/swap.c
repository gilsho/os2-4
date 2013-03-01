#include <stdio.h>
#include "swap.h"
#include <bitmap.h>
#include "devices/block.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

/* define the number of sectors per swap slot (4KB) */
#define SLOT_SECTOR_COUNT (PGSIZE / BLOCK_SECTOR_SIZE)

struct block *swap_device;					 /* swap block device handler */
static struct bitmap *swap_map;      /* bitmap, one bit per sector. */
struct lock lock_swap;							 /* swap slot for accessing bitmap */

size_t swap_reserve_slot(void);

/* initialize the swap device bitmap and designate all slots as free */
void
swap_init(void)
{
	lock_init(&lock_swap);
	swap_device = block_get_role (BLOCK_SWAP);
	size_t num_slots = (size_t) (block_size (swap_device) / SLOT_SECTOR_COUNT);
	swap_map = bitmap_create (num_slots);
	bitmap_set_all (swap_map, false);
}

/* returns the index of an available swap slot to the calling process.
   panics the kernel if no swap slots are available. */
size_t 
swap_reserve_slot(void)
{
	lock_acquire(&lock_swap);
	size_t slot_idx = bitmap_scan_and_flip (swap_map, 0, 1, false);
	if (slot_idx == BITMAP_ERROR)
		PANIC("No more swap slots.\n");
	lock_release(&lock_swap);

	return slot_idx;
}

/* release the swap slot at SLOT_IDX by clearing the
	 corresponding bitmap entry */
void
swap_release_slot(size_t slot_idx)
{
	lock_acquire(&lock_swap);
	bitmap_reset (swap_map, slot_idx);
	lock_release(&lock_swap);
}

/* reads the page data at swap slot SLOT_IDX into the 
   supplied buffer at kernel virtual address KPAGE */
void
swap_read_slot(size_t slot_idx, void *kpage)
{
	void *cur_addr = kpage;
	block_sector_t cur_sector = slot_idx * SLOT_SECTOR_COUNT;

	int i;
	for (i = 0; i < SLOT_SECTOR_COUNT; i++)
	{
		block_read (swap_device, cur_sector, cur_addr);
		cur_sector++;
		cur_addr = (void *)(((char *)cur_addr) + BLOCK_SECTOR_SIZE);
	}
	swap_release_slot(slot_idx);
}

/* writes the page data at kernel virtual address KPAGE
   into the swap device, returning the index of the
   swap slot used for storage.  */
size_t
swap_write_slot(void *kpage)
{
	size_t slot_idx = swap_reserve_slot();
	void *cur_addr = kpage;
	block_sector_t cur_sector = slot_idx * SLOT_SECTOR_COUNT;

	int i;
	for (i = 0; i < SLOT_SECTOR_COUNT; i++)
	{
		block_write (swap_device, cur_sector, cur_addr);
		cur_sector++;
		cur_addr = (void *)(((char *)cur_addr) + BLOCK_SECTOR_SIZE);
	}
	return slot_idx;
}

#include <stdio.h>
#include "swap.h"
#include <bitmap.h>
#include "devices/block.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

#if (DEBUG & DEBUG_SWAP)
#define PRINT_SWAP(X) {printf("swap: "); printf(X);}
#define PRINT_SWAP_2(X,Y) {printf("swap: "); printf(X,Y);}
#else
#define PRINT_SWAP(X) do {} while(0)
#define PRINT_SWAP_2(X,Y) do {} while(0)
#endif

#define SLOT_SECTOR_COUNT (PGSIZE / BLOCK_SECTOR_SIZE)

struct block *swap_device;
static struct bitmap *swap_map;      /* Free map, one bit per sector. */
struct lock lock_swap;

size_t swap_reserve_slot(void);

void
swap_init(void)
{
	lock_init(&lock_swap);
	swap_device = block_get_role (BLOCK_SWAP);
	size_t num_slots = (size_t) (block_size (swap_device) / SLOT_SECTOR_COUNT);
	swap_map = bitmap_create (num_slots);
	bitmap_set_all (swap_map, false);
	PRINT_SWAP_2("num slots: %d\n", (int)num_slots);
}


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

void
swap_release_slot(size_t slot_idx)
{
	lock_acquire(&lock_swap);
	bitmap_reset (swap_map, slot_idx);
	lock_release(&lock_swap);
}

void
swap_read_slot(size_t slot_idx, void *kpage)
{
	PRINT_SWAP_2("reading slot @ index: %d\n", (int)slot_idx);
	PRINT_SWAP_2("-> to kpage: %p\n", kpage);
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

#ifndef VM_FRAME_H
#define VM_FRAME_H


#include <inttypes.h>
#include "threads/thread.h"
#include <list.h>
#include "vm/pagesup.h"

extern struct list frame_list;

void frame_init_table(void);

/* This function will return a frame for use. First it tries to get a frame from the
free page pool. If it cannot find one there, it uses the clock algorithm
to evict a current page and return that frame. */
void *frame_alloc(void);

/* Installs a frame into the frame table. Caller should be holding frame table lock */
void frame_install(struct pagesup_entry *pse, void *kpage);

/* Releases the frame being held by the give page table entry. Caller must have frame table lock. */
void frame_release(struct pagesup_entry *pse);

/* Evicts the given page entry from the frame table. Caller must hold both the frame table lock and the lock for the given PSE */
void frame_evict(struct pagesup_entry *pse);

#endif /* vm/frame.h */

#ifndef VM_FRAME_H
#define VM_FRAME_H


#include <inttypes.h>
#include "threads/thread.h"
#include <list.h>
#include "vm/pagesup.h"

extern struct list frame_list;

void frame_init_table(void);
void *frame_alloc(void);
void frame_install(struct pagesup_entry *pse, void *kpage);
void frame_remove(struct pagesup_entry *pse);
void frame_release(struct pagesup_entry *pse);
void frame_evict(struct pagesup_entry *pse);

#endif /* vm/frame.h */

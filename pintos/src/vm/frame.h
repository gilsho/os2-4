#ifndef VM_FRAME_H
#define VM_FRAME_H


#include <inttypes.h>
#include "threads/thread.h"
#include <list.h>
#include "vm/pagesup.h"


void frame_init_table(void);
void *frame_alloc(void);
void frame_install(struct pagesup_entry *pse, void *kpage);
void frame_remove(struct pagesup_entry *pse);

#endif /* vm/frame.h */

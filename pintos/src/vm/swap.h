#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "threads/thread.h"

bool swap_page_in(struct thread *t);

#endif

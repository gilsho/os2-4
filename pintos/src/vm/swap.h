#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <filesys/off_t.h>


struct file *swap_file;

off_t swap_get_slot(void);


#endif

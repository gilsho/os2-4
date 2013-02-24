#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "filesys/filesys.h"
#include "vm/vman.h"
#include "vm/mmap.h"

extern struct lock lock_filesys;

typedef int pid_t;

void process_close(int status);
pid_t process_execute (const char *file_name);
int process_wait (pid_t);
void process_exit (void);
void process_activate (void);
void process_init(void);

int process_add_file_desc(struct file *file);
struct file* process_get_file_desc(int fd);
void process_remove_file_desc(int fd);


mapid_t process_map_file(void *upage, struct file * file, uint32_t file_len);
bool process_unmap_file(mapid_t mid);


#endif /* userprog/process.h */

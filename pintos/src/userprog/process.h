#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "filesys/filesys.h"

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
struct dir* process_get_wdir(void);
void process_set_wdir(struct dir *wdir);

#endif /* userprog/process.h */

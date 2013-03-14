#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "filesys/filesys.h"
#include <stdbool.h>

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

bool process_create_file(const char *path, off_t size, bool is_dir);
bool process_remove_file(const char *path);

struct dir* process_get_start_dir(const char *path);
struct file *process_open_file(const char *name);

bool process_chdir(const char *path);


#endif /* userprog/process.h */

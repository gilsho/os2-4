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

struct dir* process_get_wdir(void);
void process_set_wdir(struct dir *wdir);

bool process_create_file(const char *path, off_t size, bool is_dir);
bool process_remove_file(const char *path);

struct dir* process_get_start_dir(const char *path);
struct file *process_open_file(const char *name);

bool process_chdir(const char *path);


#endif /* userprog/process.h */

int process_fd_add_file(struct file *file);
int process_fd_add_dir(struct dir *dir);
struct file* process_fd_get_file(int fd);
struct dir* process_fd_get_dir(int fd);
bool process_fd_close(const char *path);

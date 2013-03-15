#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include <stdbool.h>
#include "filesys/off_t.h"

typedef int pid_t;

enum fd_type {
  FD_FILE,
  FD_DIR
};

union fd_content {
  struct file *file;
  struct dir *dir;
};


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
/*struct file *process_open_file(const char *name);*/

bool process_chdir(const char *path);

int process_fd_open(const char *path);

struct file* process_fd_get_file(int fd);
struct dir* process_fd_get_dir(int fd);
bool process_fd_close(int fd);
void process_fd_remove(int fd);

int process_fd_inumber(int fd);

#endif

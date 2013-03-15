#ifndef FILESYS_FILESYS_H
#define FILESYS_FILESYS_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "filesys/directory.h"

/* Sectors of system file inodes. */
#define FREE_MAP_SECTOR 0       /* Free map file inode sector. */
#define ROOT_DIR_SECTOR 1       /* Root directory file inode sector. */

/* Block device that contains the file system. */
struct block *fs_device;

void filesys_init (bool format);
void filesys_done (void);
bool filesys_create (struct dir *start_dir, 
	const char *name, off_t initial_size, bool is_dir); 

union fd_content filesys_open (struct dir *start_dir, const char *name, bool *is_dir);
struct file *filesys_open_file (struct dir *start_dir, const char *name);

bool filesys_remove (struct dir *start_dir, const char *path); 
struct dir *filesys_open_dir(struct dir *start_dir, const char *path);

#endif /* filesys/filesys.h */

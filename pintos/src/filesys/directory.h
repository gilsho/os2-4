#ifndef FILESYS_DIRECTORY_H
#define FILESYS_DIRECTORY_H

#include <stdbool.h>
#include <stddef.h>
#include "devices/block.h"
#include "filesys/file.h"

/* Maximum length of a file name component.
   This is the traditional UNIX maximum length.
   After directories are implemented, this maximum length may be
   retained, but much longer full path names must be allowed. */
#define NAME_MAX 14

#define PARENT_DIR  		".."
#define CURRENT_DIR 		"."
#define ROOT_DIR_NAME		"/"

struct inode;

/* Opening and closing directories. */

struct dir *dir_open (struct inode *);
struct dir *dir_open_root (void);
struct dir *dir_reopen (struct dir *);
void dir_close (struct dir *);
struct inode *dir_get_inode (struct dir *);
int dir_get_inumber(struct dir *dir);
block_sector_t dir_get_sector(struct dir *);

/* Reading and writing. */
bool dir_lookup (struct dir *, const char *name, struct inode **);
bool dir_add (struct dir *, const char *name, block_sector_t);
bool dir_remove (struct dir *, const char *name);
bool dir_readdir (struct dir *, char name[NAME_MAX + 1]);

void dir_init(block_sector_t sector);
bool dir_create (struct dir *parent_dir, block_sector_t sector);
bool dir_create_root(void);
struct dir* dir_open_file(struct file *file);

void dir_acquire_inode_lock(struct dir *dir);
void dir_release_inode_lock(struct dir *dir);


#endif /* filesys/directory.h */

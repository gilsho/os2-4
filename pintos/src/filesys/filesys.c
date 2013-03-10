#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/cache.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  cache_flush();
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) 
{
  /* TODO: CHECK REMOVED FLAG */
  block_sector_t inode_sector = 0;
  struct dir *dir = dir_open_root ();
  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size)
                  && dir_add (dir, name, inode_sector));
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (struct dir *start_dir, const char *path)
{          
  /* TODO: CHECK REMOVED FLAG */
  struct inode *inode = filesys_open_path(start_dir, path);
  struct file *f = file_open(inode);

  /* IS WRITING TO DIR FILES ALLOWED? */

  return file_open (inode);
}

/* Deletes the file at PATH.
   Returns true if successful, false on failure.
   Fails if no file at PATH exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (struct dir *start_dir, const char *path) 
{

  struct inode *inode = filesys_open_path(start_dir, path);

  if (inode == NULL)
    return false;

  if (inode_isdir(inode) && !dir_is_empty(inode)) {
    /* something special here */
    /* search file for used entries */
    inode_close(inode);
    return false;
  }
  else {
 
    char *name = strrchr (path, (int) '/');
    int path_len = name-path;
    if (path_len >= PGSIZE) {
      inode_close(inode);
      return false;
    }

    char *name_cpy = malloc(strnlen(name, PGSIZE));
    if (name_cpy == NULL)
      PANIC("ASSERT BAD");
    strlcpy(name_cpy, name, PGSIZE);

    char *dir_path = malloc(path_len);
    strlcpy(dir_path, path, path_len);

    struct dir *parent_dir = filesys_open_dir(start_dir, dir_path);
    ASSERT(parent_dir != NULL);

    /* TODO: CHECK FOR ROOT? */
    success = dir_remove(parent_dir, name);
    dir_close (parent_dir); 
  } 

  return success;
}


/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...\n");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}


struct dir *
filesys_open_dir(struct dir *start_dir, const char *path)
{
  struct inode *inode = filesys_open_path(start_dir, path);
  return dir_open(inode);
}

/* Returns an open inode for the child file/dir PATH
   of START_DIR */
struct *inode 
filesys_open_path(struct dir *start_dir, char *path) 
{
  /* copy the path arg string */
  size_t len = strnlen (path,PGSIZE);
  char *pathcpy = malloc(len);
  if (pathcpy == NULL)
    return NULL;
  memcpy(pathcpy,path,len);

  /* tokenize */
  struct inode *inode;
  char *token, *next_token, *save_ptr;
  struct dir *cur_dir = dir_reopen (start_dir);

  token = strtok_r (pathcpy, "/", &save_ptr);
  while ( token != NULL )
  {
    bool found = dir_lookup(cur_dir,token,&inode);

    /* entry not found in current directory */
    if (!found) {
      dir_close(cur_dir);
      break;
    }

    next_token = strtok_r (NULL, "/", &save_ptr);

    /* check if reached end of path */
    if (next_token == NULL)
      break;

    dir_close(cur_dir);
    cur_dir = dir_open(inode);

    /* check if trying to descend into a file */
    if (cur_dir == NULL)
      return NULL;
    
    token = next_token;
  }
  return inode;
}

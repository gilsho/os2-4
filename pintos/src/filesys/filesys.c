#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/cache.h"
#include "userprog/process.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"


/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

bool split_path(const char *path, char **parent_path, char **name);

bool filesys_resolve_path(struct dir* start_dir, const char *path, 
  struct dir **parent_dir, char **name);

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


/* caller must free name */
bool filesys_resolve_path(struct dir* start_dir, const char *path, 
  struct dir **parent_dir, char **name){

  char *parent_path = NULL;
  struct inode *inode = NULL;
  bool success = false;

  if(!split_path(path, &parent_path, name))
    goto done;


  if(!dir_lookup(start_dir, parent_path, &inode))
    goto done;

  *parent_dir = dir_open(inode);


  if (*parent_dir == NULL)
  {
    goto done;
  }

  success = true;
  
  done:
    if (parent_path != NULL)
      free(parent_path);
    /* Should we free inode??*/

  return success;
}



/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (struct dir *start_dir, const char *path, off_t initial_size, bool is_dir) 
{
  /* TODO: CHECK REMOVED FLAG */
  bool success = false;
  block_sector_t inode_sector = 0;
  char *name = NULL;
  struct dir *parent_dir = NULL;
  /*PRINT_FCREATE_2("start dir 1: %p\n", start_dir);*/
  start_dir = dir_reopen(start_dir);



  if(start_dir == NULL)
    goto done;


  if(!filesys_resolve_path(start_dir, path, &parent_dir, &name))
    goto done;

  if(parent_dir == NULL || name == NULL)
    goto done;

  dir_acquire_inode_lock(parent_dir);

  if(dir_lookup(parent_dir, name, NULL))
    goto done;

  if(!free_map_allocate (1, &inode_sector))
    goto done;


  if (strnlen(name, PGSIZE) > NAME_MAX)
    goto done;

  if(is_dir){
    if(!dir_create(parent_dir, inode_sector))
      goto done;
  }else{
    if(!file_create(inode_sector, initial_size))
      goto done;
  }
  if(!dir_add (parent_dir, name, inode_sector))
    goto done;

  success = true;

  done:
    if(parent_dir != NULL && name != NULL)
      dir_release_inode_lock(parent_dir);

    if(name != NULL)
      free(name);
    if(parent_dir != NULL){
      dir_close(parent_dir);
      parent_dir = NULL;
    }

    if(start_dir != NULL){
      dir_close(start_dir);
      start_dir = NULL;
    }
    if (!success && inode_sector != 0) {
      inode_destroy(inode_sector);
    }
  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
/*struct file * */
struct file*
filesys_open_file (struct dir *start_dir, const char *path)
{         
  struct inode *inode = NULL;
  dir_lookup(start_dir,path,&inode);

  return file_open(inode);
}

/* Opens a file or directory at PATH with base directory
   START_DIR. Returns a new file descriptor table entry,
   which indicates the type of object */
union fd_content
filesys_open (struct dir *start_dir, const char *path, enum fd_type *type)
{         
  struct inode *inode = NULL;
  dir_lookup(start_dir,path,&inode);

  union fd_content content;
  content.file = NULL;

  if (inode == NULL)
    return content;
  
  if (inode_is_removed(dir_get_inode(start_dir))) {
    inode_close(inode);
    return content;
  }

  if (inode_isdir(inode)) {
    content.dir = dir_open(inode);
    *type = FD_DIR;
  }  
  else {
    content.file = file_open(inode);
    *type = FD_FILE;
  }
  return content;
}


/* Deletes the file at PATH.
   Returns true if successful, false on failure.
   Fails if no file at PATH exists,
   or if an internal memory allocation fails. */

   /* caller has to open and close start_dir */
bool
filesys_remove (struct dir *start_dir, const char *path) 
{
  bool success = false;
  struct inode *inode = NULL;
  char *parent_path = NULL;
  char *name        = NULL;
  struct dir *parent_dir = NULL;

  start_dir = dir_reopen(start_dir);

  ASSERT (start_dir != NULL);
  ASSERT (path != NULL);

  /* Check NAME for validity. */
  if (*path == '\0')
    return false;

  if (!split_path(path, &parent_path, &name))
    return false;

  if (strnlen(name, PGSIZE) > NAME_MAX)
    goto done;

  if (!dir_lookup(start_dir, parent_path, &inode))
    goto done;

  parent_dir = dir_open(inode);
  if (parent_dir == NULL)
    goto done;

  if (!dir_remove(parent_dir, name))
    goto done;

  success = true;

  done:
    if (parent_path != NULL)
      free(parent_path);
    if (name != NULL)
      free(name);
    if(start_dir != NULL)
      dir_close(start_dir);
    if (parent_dir != NULL)
      dir_close(parent_dir);
    else if (inode != NULL)
      inode_close(inode);


    return success;
}


/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...\n");
  free_map_create ();
  if (!dir_create_root())
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}


/* returns an open inode */
struct dir *
filesys_open_dir(struct dir *start_dir, const char *path)
{
  struct inode *inode = NULL;
  dir_lookup(start_dir,path,&inode);

  /* IS WRITING TO DIR FILES ALLOWED? */
  return dir_open(inode);
}

bool
split_path(const char *path, char **parent_path, char **name)
{

  /*bool success = false;*/

  int full_len = strnlen(path, PGSIZE);
  if (full_len == PGSIZE || full_len == 0)
    return false;

  int parent_len = 0;
  const char *pivot = strrchr (path, (int) '/');
  if(pivot != NULL){

    parent_len = pivot - path;
    *parent_path = calloc(parent_len + 1, sizeof(char));
    if(*parent_path == NULL){
      PANIC("Could not allocate parent path");
    }

    memcpy(*parent_path, path, parent_len);

    pivot++;

  }else{
    *parent_path = calloc(1, sizeof(char));
    if(*parent_path == NULL)
      PANIC("Could not allocate parent_path");
    pivot = path;
  }

  int name_len = strnlen(pivot, PGSIZE);

  *name = calloc(name_len+1, sizeof(char));
  if(*name == NULL)
      PANIC("Could not allocate name");
  
  memcpy(*name, pivot, name_len);


  return true;
}


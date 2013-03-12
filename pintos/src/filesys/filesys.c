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

#if (DEBUG & DEBUG_FILESYS)
#define DEBUG_FCREATE       1
#endif

#if DEBUG_FCREATE
#define PRINT_FCREATE(X) {printf("(filesys-create) "); printf(X);}
#define PRINT_FCREATE_2(X,Y) {printf("(filesys-create) "); printf(X,Y);}
#else
#define PRINT_FCREATE(X) do {} while(0)
#define PRINT_FCREATE_2(X,Y) do {} while(0)
#endif



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
  PRINT_FCREATE_2("name: %s\n", name);
  /* TODO: CHECK REMOVED FLAG */
  block_sector_t inode_sector = 0;
  struct dir *dir = dir_open_root ();
  /*bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size)
                  && dir_add (dir, name, inode_sector));*/
  bool success = dir != NULL;
  PRINT_FCREATE_2("dir != NULL: %d\n", (int)success);
  success = success & free_map_allocate (1, &inode_sector);
  PRINT_FCREATE_2("free_map_allocate success: %d\n", (int)success);
  /*PRINT_FCREATE_2("inode_sector: %d\n", inode_sector);*/
  success = success & inode_create (inode_sector, initial_size);
  PRINT_FCREATE_2("inode_create success: %d\n", (int)success);
  PRINT_FCREATE_2("1 dir->inode->sector: %d\n", (int)dir_get_sector(dir));
  success = success & dir_add (dir, name, inode_sector);
  PRINT_FCREATE_2("2 dir->inode->sector: %d\n", (int)dir_get_sector(dir));
  PRINT_FCREATE_2("dir_add success: %d\n", (int)success);

  
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);

  PRINT_FCREATE_2("returning: %d\n", (int)success);
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

  struct inode *inode = NULL;
  dir_lookup(start_dir,path,&inode);

  /* IS WRITING TO DIR FILES ALLOWED? */
  return file_open (inode);
}

/* Deletes the file at PATH.
   Returns true if successful, false on failure.
   Fails if no file at PATH exists,
   or if an internal memory allocation fails. */

   /* caller has to open and close start_dir */
bool
filesys_remove (struct dir *start_dir, const char *path) 
{
  return dir_remove(start_dir, path);
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
   struct inode *inode = NULL;
  dir_lookup(start_dir,path,&inode);

  /* IS WRITING TO DIR FILES ALLOWED? */
  return dir_open(inode);
}


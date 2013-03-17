#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"

/* A directory. */
struct dir 
  {
    struct inode *inode;                /* Backing store. */
    off_t pos;                          /* Current position. */
  };

/* A single directory entry. */
struct dir_entry 
  {
    block_sector_t inode_sector;        /* Sector number of header. */
    char name[NAME_MAX + 1];            /* Null terminated file name. */
    bool in_use;                        /* In use or free? */
  };


#define EMPTY_DIR_SIZE (2 * sizeof(struct dir_entry))

bool add_entry(struct dir *dir, const char *name, block_sector_t inode_sector);
bool remove_entry(struct dir *dir, const char *name);
bool dir_is_empty(struct inode *inode);


bool
dir_create_root(void){
  if(!inode_create (ROOT_DIR_SECTOR, EMPTY_DIR_SIZE, true))
    return false;

  struct dir *my_dir;
  if( (my_dir = dir_open(inode_open(ROOT_DIR_SECTOR)) ) ){

    bool success = dir_add(my_dir, CURRENT_DIR, ROOT_DIR_SECTOR) &&
                  dir_add(my_dir, CURRENT_DIR, ROOT_DIR_SECTOR);
     dir_close(my_dir);

     return success;

  }
  return false;
}

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (struct dir *parent_dir, block_sector_t sector)
{
  if(!inode_create (sector, EMPTY_DIR_SIZE, true))
    return false;

  struct dir *my_dir;
  if( (my_dir = dir_open(inode_open(sector)) ) ){

    bool success = dir_add(my_dir, CURRENT_DIR, sector) &&
                   dir_add(my_dir, PARENT_DIR, dir_get_sector(parent_dir));
    dir_close(my_dir);
    return success;
  }
  return false;
}


/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode) 
{
  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && dir != NULL && inode_isdir(inode))
    {
      dir->inode = inode;
      dir->pos = 0;
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL; 
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir) 
{
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) 
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) 
{
  return dir->inode;
}

block_sector_t 
dir_get_sector(struct dir *dir)
{
  return inode_get_sector(dir->inode);
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp) 
{
  struct dir_entry e;
  size_t ofs;
  
  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) {
    if (e.in_use && !strcmp (name, e.name)) 
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        return true;
      }
  }
  return false;
}

/* Searches DIR for a specific PATH
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (struct dir *start_dir, const char *path,
            struct inode **inode) 
{
  struct dir_entry e;

  ASSERT (start_dir != NULL);
  ASSERT (path != NULL);

  /* +1 open_cnt for start_dir */
  struct dir *cur_dir = dir_reopen (start_dir);


  /* copy the path arg string */
  size_t len = strnlen (path,PGSIZE);

  if (len == 0)
  {
    *inode = start_dir->inode;
    /* -1 open_cnt for start_dir */
    free(cur_dir);
    return true;
  }

  char *pathcpy = malloc(len+1);
  if (pathcpy == NULL)
    return false;
  memcpy(pathcpy,path,len+1);

  char *token, *next_token, *save_ptr;
  struct inode *cur_inode = cur_dir->inode;

  token = strtok_r (pathcpy, "/", &save_ptr);

  while (token != NULL) {
    if(lookup (cur_dir, token, &e, NULL)) {
      /* +1 token inode */
      cur_inode = inode_open (e.inode_sector);
    } else {
      /* -1 current directory */
      dir_close(cur_dir);
      return false; /* entry doesn't exist in directory */
    }

    next_token = strtok_r (NULL, "/", &save_ptr);

    dir_close(cur_dir);

    /* check if reached end of path */
    if (next_token == NULL) {
      break;
    }

    /* +0 subdirectory */
    cur_dir = dir_open(cur_inode);

    /* check if trying to descend into a file */
    if (cur_dir == NULL) {
      inode_close(cur_inode);
      return false;
    }
    
    token = next_token;
  }

  if (inode != NULL)
    *inode = cur_inode;
  else
    inode_close(cur_inode);
  
  return true;
}


/* adds a directory entry to DIR with NAME
   at i-number/sector INODE_SECTOR */
bool
dir_add(struct dir *parent_dir, const char *name, block_sector_t inode_sector)
{
  struct dir_entry e;
  off_t ofs;
  bool success;

  if (inode_is_removed(parent_dir->inode))
    return false;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.
     
     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (parent_dir->inode, &e, sizeof e, ofs)
                                                                 == sizeof e;
       ofs += sizeof e) 
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;

  success = inode_write_at (parent_dir->inode, &e, sizeof e, ofs) == sizeof e;
  return success;
}

bool
dir_remove(struct dir *dir, const char *name)
{
  struct dir_entry e;
  off_t ofs;
  bool success = false;
  struct inode *inode = NULL;

  if(strcmp(name, PARENT_DIR) == 0 || strcmp(name, CURRENT_DIR) == 0)
    return false;

  inode_acquire_dir_lock(dir->inode);

  /* Find directory entry. */
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* Open inode. */

  inode = inode_open (e.inode_sector);
  if (inode == NULL || (inode_isdir(inode) && !dir_is_empty(inode)))
    goto done;

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e) 
    goto done;

  /* Remove inode. */
  inode_remove (inode);

  

  success = true;

 done:
  inode_release_dir_lock(dir->inode);
  if (inode != NULL)
    inode_close (inode);
  return success;
}

struct dir* 
dir_open_file(struct file *file){
  return dir_open(inode_reopen(file_get_inode(file)));
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  struct dir_entry e;

  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e) 
    {
      dir->pos += sizeof e;
      if (e.in_use)
        {
          strlcpy (name, e.name, NAME_MAX + 1);
          if(strcmp(name, PARENT_DIR) == 0 || strcmp(name, CURRENT_DIR) == 0)
            continue;
          return true;
        } 
    }
  return false;
}

/* tries to find an entry in the directory listing that is not PARENT_DIR
   or CURRENT_DIR */
bool
dir_is_empty(struct inode *inode){
  if(inode == NULL)
    return false;

  struct dir_entry e;
  off_t pos = 0;
  char name[NAME_MAX + 1];

  while (inode_read_at (inode, &e, sizeof e, pos) == sizeof e) 
  {
    pos += sizeof e;
    if (e.in_use)
      {
        strlcpy (name, e.name, NAME_MAX + 1);
        if(strcmp(name, PARENT_DIR) == 0 || strcmp(name, CURRENT_DIR) == 0)
          continue;
        /* found entry that is not current or parent */
        return false;
      } 
  }
  return true;
}

int 
dir_get_inumber(struct dir *dir) 
{
  return (int) inode_get_sector(dir->inode);
}

void
dir_acquire_inode_lock(struct dir *dir){
  inode_acquire_dir_lock(dir->inode);
}

void
dir_release_inode_lock(struct dir *dir){
  inode_release_dir_lock(dir->inode);
}


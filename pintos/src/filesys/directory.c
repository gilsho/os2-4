#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"

#if (DEBUG & DEBUG_DIR)
#define DEBUG_ADD        1
#define DEBUG_SPLIT      1
#define DEBUG_LOOKUP     1
#endif

#if DEBUG_ADD
#define PRINT_ADD(X) {printf("(dir-add) "); printf(X);}
#define PRINT_ADD_2(X,Y) {printf("(dir-add) "); printf(X,Y);}
#else
#define PRINT_ADD(X) do {} while(0)
#define PRINT_ADD_2(X,Y) do {} while(0)
#endif

#if DEBUG_SPLIT
#define PRINT_SPLIT(X) {printf("(dir-split) "); printf(X);}
#define PRINT_SPLIT_2(X,Y) {printf("(dir-split) "); printf(X,Y);}
#else
#define PRINT_SPLIT(X) do {} while(0)
#define PRINT_SPLIT_2(X,Y) do {} while(0)
#endif

#if DEBUG_LOOKUP
#define PRINT_LOOKUP(X) {printf("(dir-lookup) "); printf(X);}
#define PRINT_LOOKUP_2(X,Y) {printf("(dir-lookup) "); printf(X,Y);}
#else
#define PRINT_LOOKUP(X) do {} while(0)
#define PRINT_LOOKUP_2(X,Y) do {} while(0)
#endif


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


bool split_path(const char *path, char **parent_path, char **name);
bool add_entry(struct dir *dir, const char *name, block_sector_t inode_sector);
bool remove_entry(struct dir *dir, const char *name);


/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (block_sector_t sector, size_t entry_cnt)
{
  return inode_create (sector, entry_cnt * sizeof (struct dir_entry));
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

  PRINT_LOOKUP_2("start_dir->inode->sector: %d\n", 
    inode_get_sector(start_dir->inode));
  struct dir *cur_dir = dir_reopen (start_dir);

  PRINT_LOOKUP_2("path: %s\n", path);

  /* copy the path arg string */
  size_t len = strnlen (path,PGSIZE);

  if (len == 0)
  {
    *inode = start_dir->inode;
    return true;
  }

  char *pathcpy = malloc(len+1);
  if (pathcpy == NULL)
    return false;
  memcpy(pathcpy,path,len+1);

  PRINT_LOOKUP_2("pathcpy: %s\n", pathcpy);

  char *token, *next_token, *save_ptr;
  struct inode *cur_inode = cur_dir->inode;

  token = strtok_r (pathcpy, "/", &save_ptr);

  while (token != NULL) {
    
    if(lookup (cur_dir, token, &e, NULL)) {
      cur_inode = inode_open (e.inode_sector);
    } else {
      dir_close(cur_dir);
      return false; /* entry doesn't exist in directory */
    }

    next_token = strtok_r (NULL, "/", &save_ptr);

    dir_close(cur_dir);

    /* check if reached end of path */
    if (next_token == NULL) {
      break;
    }

    cur_dir = dir_open(cur_inode);

    /* check if trying to descend into a file */
    if (cur_dir == NULL)
      return false;
    
    token = next_token;
  }

  if (inode != NULL)
    *inode = cur_inode;
  return true;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct dir *start_dir, const char *path, block_sector_t inode_sector)
{
  PRINT_ADD_2("start_dir->inode->sector: %d\n", inode_get_sector(start_dir->inode));
  PRINT_ADD_2("inode_sector: %d\n", inode_sector);

  bool success = false;
  struct inode *inode = NULL;
  char *parent_path = NULL;
  char *name        = NULL;

  ASSERT (start_dir != NULL);
  ASSERT (path != NULL);

  /* Check NAME for validity. */
  if (*path == '\0')
    goto done; 

  PRINT_ADD("0\n");

  if (!split_path(path, &parent_path, &name))
    goto done;

  PRINT_ADD("1\n");

  if (strnlen(name, PGSIZE) > NAME_MAX)
    goto done;

  PRINT_ADD("2\n");

  if (!dir_lookup(start_dir, parent_path, &inode))
    goto done;

  PRINT_ADD_2("new inode->sector: %d\n", inode_get_sector(inode));


  PRINT_ADD("3\n");

  struct dir *parent_dir = dir_open(inode);
  if (parent_dir == NULL)
  {
    PRINT_ADD("unable to open parent dir\n");
    inode = NULL;
    goto done;
  }

  PRINT_ADD_2("before add entry -> start_dir->inode->sector: %d\n", 
    inode_get_sector(start_dir->inode));
  PRINT_ADD_2("before add entry -> parent_dir->inode->sector: %d\n", 
    inode_get_sector(parent_dir->inode));

  if (!add_entry(parent_dir, name, inode_sector))
    goto done;

  PRINT_ADD_2("after add entry -> start_dir->inode->sector: %d\n", 
    inode_get_sector(start_dir->inode));
  PRINT_ADD_2("after add entry -> parent_dir->inode->sector: %d\n", 
    inode_get_sector(parent_dir->inode));

  success = true;

  done:
    if (parent_path != NULL)
      free(parent_path);
    if (name != NULL)
      free(name);
    /*if (inode != NULL)
      free(inode);*/
    return success;
}

bool
split_path(const char *path, char **parent_path, char **name)
{
  PRINT_SPLIT_2("path: %s\n", path);

  bool success = false;

  int full_len = strnlen(path, PGSIZE);
  if (full_len == PGSIZE)
    goto done;

  char *pathcpy = NULL;
  pathcpy = malloc(full_len+2);
  if (pathcpy == NULL)
    goto done;

  pathcpy[0] = '/';
  memcpy(pathcpy+1, path, full_len+1);

  char *pivot = strrchr (pathcpy, (int) '/');

  PRINT_SPLIT_2("pivot: %s\n", pivot);

  int parent_path_len = pivot - pathcpy;
  int name_len        = full_len - parent_path_len - 1;

  PRINT_SPLIT_2("parent_path_len: %d\n", parent_path_len);
  PRINT_SPLIT_2("name_len: %d\n", name_len);  

  *parent_path = calloc(parent_path_len+1, sizeof(char));
  if (*parent_path == NULL)
    goto done;

  *name = calloc(name_len+1, sizeof(char));
  if (*name == NULL)
    goto done;

  memcpy(*parent_path, path, parent_path_len);
  *parent_path[parent_path_len]=0;

  memcpy(*name, pivot+1, name_len+1);

  PRINT_SPLIT_2("parent_path: %s\n", *parent_path);
  PRINT_SPLIT_2("name: %s\n", *name);

  success = true;

  done:
    if (pathcpy != NULL)
      free(pathcpy);
    return success;
}

/* adds a directory entry to DIR with NAME
   at i-number/sector INODE_SECTOR */
bool
add_entry(struct dir *dir, const char *name, block_sector_t inode_sector)
{
  struct dir_entry e;
  off_t ofs;
  bool success;
  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.
     
     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;

  PRINT_ADD_2("e.in_use: %d\n", (int) e.in_use);
  PRINT_ADD_2("e.inode_sector: %d\n", (int) e.inode_sector);

  success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *start_dir, const char *path) 
{
  bool success = false;
  struct inode *inode = NULL;
  char *parent_path = NULL;
  char *name        = NULL;

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

  struct dir *parent_dir = dir_open(inode);
  if (parent_dir == NULL)
  {
    inode = NULL;
    goto done;
  }

  if (!remove_entry(parent_dir, name))
    goto done;

  success = true;

  done:
    if (parent_path != NULL)
      free(parent_path);
    if (name != NULL)
      free(name);
    if (inode != NULL)
      inode_close(inode);
    return success;
}

bool
remove_entry(struct dir *dir, const char *name)
{
  struct dir_entry e;
  off_t ofs;
  bool success = false;
  struct inode *inode = NULL;

  /* Find directory entry. */
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e) 
    goto done;

  /* Remove inode. */
  inode_remove (inode);
  success = true;

 done:
  inode_close (inode);
  return success;
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
          return true;
        } 
    }
  return false;
}

#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/cache.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include <stdio.h>


/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define N_DIRECT_PTRS 12
#define N_INDIRECT_PTRS (BLOCK_SECTOR_SIZE/sizeof(block_sector_t))
#define N_DBL_INDIRECT_PTRS (N_INDIRECT_PTRS * N_INDIRECT_PTRS)

#define UNUSED_SECTOR 0

#define UNUSED_WORDS 111

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    block_sector_t direct[N_DIRECT_PTRS];  /* first-order data sector. */
    block_sector_t indirect;
    block_sector_t dbl_indirect;
    off_t length;                          /* File size in bytes. */
    bool is_dir;                           /* True if inode is a director*/
    unsigned magic;                        /* Magic number. */
    uint32_t unused[UNUSED_WORDS];                  /* Not used. */
  };

/* Returns the block number that contains the byte offset of a file */
static inline size_t
byte_to_block (off_t byte_ofs)
{
  return byte_ofs / BLOCK_SECTOR_SIZE;
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct lock lock_dir;               /* used for adding/removing from directory */
    struct lock lock_file;              /* Used to check metadata of file */
    bool extending;                     /* flag for if file is currently being extended*/
    struct condition ready_to_extend;   /* condition variable to wait on file being ready to extend */
  };


void inode_free_sectors(struct inode *inode, int start_block,
                                        int end_block);
off_t inode_length(const struct inode *inode);
void inode_set_length(struct inode *inode, int length);
block_sector_t inode_get_direct_sector(const struct inode *inode, int index);
void inode_set_direct_sector(const struct inode *inode, int index, block_sector_t direct);
block_sector_t inode_get_indirect_sector_table(const struct inode *inode);
void inode_set_indirect_sector_table(const struct inode *inode, block_sector_t indirect);
block_sector_t inode_get_dbl_indirect_sector_table(const struct inode *inode);
void inode_set_dbl_indirect_sector_table(const struct inode *inode, block_sector_t dbl_indirect);
block_sector_t inode_get_sector_table_entry(block_sector_t sector_table, int index);
void inode_set_sector_table_entry(block_sector_t sector_table, int index, block_sector_t sector_entry);
off_t inode_extend(struct inode *inode, int old_length, int new_length);
void inode_zero_sector(block_sector_t sector, bool meta);



off_t 
inode_length(const struct inode *inode) 
{
  size_t length;
  off_t sector_ofs = offsetof (struct inode_disk, length);
  cache_read (inode->sector, FETCH_NONE, &length, sector_ofs, sizeof(size_t),true); 
  return length;
} 

void 
inode_set_length(struct inode *inode, int length)
{
  off_t sector_ofs = offsetof (struct inode_disk, length);
  cache_write (inode->sector, FETCH_NONE, &length, sector_ofs, sizeof(size_t),true); 
}

block_sector_t 
inode_get_direct_sector(const struct inode *inode, int index)
{
  block_sector_t direct[N_DIRECT_PTRS];
  off_t sector_ofs = offsetof (struct inode_disk, direct);
  cache_read (inode->sector, FETCH_NONE, 
          &direct, sector_ofs, sizeof(block_sector_t)*N_DIRECT_PTRS,true); 
  return direct[index];
}

void
inode_set_direct_sector(const struct inode *inode, int index, block_sector_t direct)
{
  off_t sector_ofs = offsetof (struct inode_disk, direct) + index * sizeof(block_sector_t);
  cache_write (inode->sector, FETCH_NONE, 
          &direct, sector_ofs, sizeof(block_sector_t),true); 
}

block_sector_t 
inode_get_indirect_sector_table(const struct inode *inode)
{
  block_sector_t indirect;
  off_t sector_ofs = offsetof(struct inode_disk, indirect);
  cache_read(inode->sector, FETCH_NONE, 
          &indirect, sector_ofs, sizeof(block_sector_t),true);
  return indirect;
}

void
inode_set_indirect_sector_table(const struct inode *inode, block_sector_t indirect)
{
  off_t sector_ofs = offsetof(struct inode_disk, indirect);
  cache_write(inode->sector, FETCH_NONE,
          &indirect, sector_ofs, sizeof(block_sector_t),true);
}

block_sector_t 
inode_get_dbl_indirect_sector_table(const struct inode *inode)
{
  block_sector_t dbl_indirect;
  off_t sector_ofs = offsetof(struct inode_disk,dbl_indirect);
  cache_read(inode->sector, FETCH_NONE,
        &dbl_indirect, sector_ofs, sizeof(block_sector_t),true); 
  return dbl_indirect;
}

void
inode_set_dbl_indirect_sector_table(const struct inode *inode, block_sector_t dbl_indirect)
{
  off_t sector_ofs = offsetof(struct inode_disk,dbl_indirect);
  cache_write(inode->sector, FETCH_NONE,
        &dbl_indirect, sector_ofs, sizeof(block_sector_t),true); 
}

block_sector_t 
inode_get_sector_table_entry(block_sector_t sector_table, int index)
{
  block_sector_t sector_entry;
  off_t sector_ofs =  index * sizeof(block_sector_t);
  cache_read (sector_table, FETCH_NONE,
        &sector_entry, sector_ofs, sizeof(block_sector_t),true); 
  return sector_entry;
}

void
inode_set_sector_table_entry(block_sector_t sector_table, int index, block_sector_t sector_entry)
{ 
  off_t sector_ofs =  index * sizeof(block_sector_t);
  cache_write (sector_table, FETCH_NONE,
      &sector_entry, sector_ofs, sizeof(block_sector_t),true); 
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t length, off_t pos) 
{
  ASSERT (inode != NULL);

  int block_num = pos/BLOCK_SECTOR_SIZE;


  if (pos < 0 || pos >= length)
    return -1;


  if (block_num < N_DIRECT_PTRS) {
    return inode_get_direct_sector(inode,block_num);
  }

  else if (block_num < (int)(N_DIRECT_PTRS + N_INDIRECT_PTRS)) 
  {

    int trunc_block_num = (block_num - N_DIRECT_PTRS);

    block_sector_t indirect_table = inode_get_indirect_sector_table(inode);
    return inode_get_sector_table_entry(indirect_table,trunc_block_num);
  } 

  else if (block_num < (int) (N_DBL_INDIRECT_PTRS + N_INDIRECT_PTRS + N_DIRECT_PTRS)) 
  {    
    int trunc_block_num = (block_num - N_DIRECT_PTRS - N_INDIRECT_PTRS);
    block_sector_t dbl_indirect_table = inode_get_dbl_indirect_sector_table(inode);
    
    int index = trunc_block_num / N_INDIRECT_PTRS;
    block_sector_t indirect_table = inode_get_sector_table_entry(dbl_indirect_table,index);

    index = trunc_block_num % N_INDIRECT_PTRS;
    return inode_get_sector_table_entry(indirect_table,index);
  } 

  else {
    /* file too big */
    PANIC("file access exceeded max file capacity");
    return -1;
  }

}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;
static struct lock inode_list_lock;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
  lock_init(&inode_list_lock);

}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, bool is_dir)
{

  ASSERT (length >= 0);
  struct inode_disk *disk_inode = NULL;

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode == NULL)
    return false;

  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode->length = 0;
  disk_inode->magic = INODE_MAGIC;
  disk_inode->is_dir = is_dir;

  cache_write(sector, FETCH_NONE, disk_inode, 0, BLOCK_SECTOR_SIZE, true);

  /* dummy i-node for file initialization */
  struct inode inode;
  inode.sector = sector;
  
  off_t my_length = inode_extend(&inode, disk_inode->length, length);
  inode_set_length(&inode, my_length);

  free (disk_inode);
    
  return my_length == length;
}


void
inode_free_sectors(struct inode *inode, int start_block,
                                        int end_block)
{

  ASSERT(end_block >= start_block);
  ASSERT(end_block < (int) (N_DIRECT_PTRS + N_INDIRECT_PTRS + N_DBL_INDIRECT_PTRS));

  if(inode_length(inode) <= 0)
    return;
  int cur_block;
  for (cur_block = end_block; cur_block >= start_block; cur_block--)
  {
    /* clean up direct data sectors */
    if (cur_block < N_DIRECT_PTRS)
    {
      block_sector_t stale_sector = inode_get_direct_sector(inode,cur_block);

      free_map_release (stale_sector, 1);
      inode_set_direct_sector(inode,cur_block,0); 
    }

    /* clean up indirect sectors, meta & data */
    else if (cur_block < (int)(N_DIRECT_PTRS + N_INDIRECT_PTRS))
    {

      block_sector_t indirect_table = inode_get_indirect_sector_table(inode);

      int trunc_cur_block = cur_block - N_DIRECT_PTRS;
      block_sector_t stale_sector = inode_get_sector_table_entry(indirect_table, trunc_cur_block);
      free_map_release (stale_sector, 1);
      inode_set_sector_table_entry(indirect_table,trunc_cur_block,0);


      if (cur_block == N_DIRECT_PTRS) {
        free_map_release(indirect_table,1);
        inode_set_indirect_sector_table(inode,UNUSED_SECTOR);
      }


    }

    /* clean up dbl indirect sectors, meta & data */
    else
    {

      int trunc_cur_block = cur_block - N_DIRECT_PTRS - N_INDIRECT_PTRS;
      int dbl_indirect_idx = trunc_cur_block / BLOCK_SECTOR_SIZE;
      int indirect_idx = trunc_cur_block % BLOCK_SECTOR_SIZE;

      block_sector_t dbl_indirect_table = inode_get_dbl_indirect_sector_table(inode);
      block_sector_t indirect_table = inode_get_sector_table_entry(dbl_indirect_table,
                                      dbl_indirect_idx);
      block_sector_t stale_sector = inode_get_sector_table_entry(indirect_table, 
                                      indirect_idx);

      free_map_release(stale_sector,1);
      inode_set_sector_table_entry(indirect_table, indirect_idx, 0);

      if (indirect_idx == 0) {
        free_map_release(indirect_table,1);
        inode_set_sector_table_entry(dbl_indirect_table,dbl_indirect_idx,UNUSED_SECTOR);
      }

      if (cur_block == N_DIRECT_PTRS + N_INDIRECT_PTRS) {
        free_map_release(dbl_indirect_table,1);
        inode_set_dbl_indirect_sector_table(inode,UNUSED_SECTOR);
      }

    }

  }

}


/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  lock_acquire(&inode_list_lock);
  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);

      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          lock_release(&inode_list_lock);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL){
    lock_release(&inode_list_lock);
    return NULL;
  }

  /* Initialize. */
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  inode->extending = false;
  cond_init(&inode->ready_to_extend);
  lock_init(&inode->lock_dir);
  lock_init(&inode->lock_file);
  list_push_front (&open_inodes, &inode->elem);

  lock_release(&inode_list_lock);

  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

void 
inode_destroy(block_sector_t sector)
{
  struct inode *inode = inode_open(sector);
  inode_remove(inode);
  inode->open_cnt = 0;
  inode_close(inode);
}


bool
inode_is_removed(struct inode * inode)
{
  return (inode->removed);
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{

  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  inode->open_cnt--;

  /* Release resources if this was the last opener. */
  if (inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      lock_acquire(&inode_list_lock);
      list_remove (&inode->elem);
      lock_release(&inode_list_lock);
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          /* Should this be on stack? Malloc? */
          block_sector_t end_block = byte_to_block(inode_length(inode));
          inode_free_sectors(inode,0,end_block);


          free_map_release (inode->sector, 1);
        }

      free (inode); 
    }

}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;

  lock_acquire(&(inode->lock_file));
  off_t length = inode_length(inode);
  lock_release(&(inode->lock_file));

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, length, offset);
      block_sector_t next_sector_idx = byte_to_sector (inode, length, offset+BLOCK_SECTOR_SIZE);

      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = length - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;


      cache_read(sector_idx, next_sector_idx, buffer + bytes_read, sector_ofs, 
                  chunk_size, false);
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }


  return bytes_read;
}

off_t 
inode_extend(struct inode *inode, int old_length, int new_length)
{
  /* returns the requested file size in bytes. caller must set length */
  ASSERT(new_length >= 0);

  if (new_length == 0 || new_length <= old_length)
    return old_length;

  int length = old_length;

  int end_block = (length == 0) ? -1 : (int) byte_to_block(length);
  int end_write_block = byte_to_block(new_length);

  bool success = true;


  int cur_block;
  for (cur_block = end_block+1; cur_block <= end_write_block; cur_block++)
  {
    /* allocate new direct sector */
    if (cur_block < N_DIRECT_PTRS) 
    {
      block_sector_t new_sector;
      if (!free_map_allocate (1,&new_sector)){
        success = false;
        break;
      }
      inode_zero_sector(new_sector, true);
      inode_set_direct_sector(inode, cur_block, new_sector);
    }


    /* allocate new indirect sector */
    else if (cur_block < (int)(N_INDIRECT_PTRS + N_DIRECT_PTRS))
    {
      /* allocate new indirec table if necessary */
      block_sector_t indirect_table = inode_get_indirect_sector_table(inode);
      if (indirect_table == UNUSED_SECTOR)
      {
        if (!free_map_allocate(1, &indirect_table)) {
          success = false;
          break;
        }
        inode_zero_sector(indirect_table, true);
        inode_set_indirect_sector_table(inode, indirect_table);
      }

      block_sector_t new_sector;
      if (!free_map_allocate(1, &new_sector)) {
        success = false;
        break;
      }
      inode_zero_sector(new_sector, true);
      int indirect_index = cur_block - N_DIRECT_PTRS;
      inode_set_sector_table_entry(indirect_table, indirect_index, new_sector);
    }

    /* allocate new double indirect sector */
    else if (cur_block <  (int) (N_DBL_INDIRECT_PTRS + N_INDIRECT_PTRS + N_DIRECT_PTRS))
    {
      /* allocate double indirect table if necessary */
      block_sector_t dbl_indirect_table = inode_get_dbl_indirect_sector_table(inode);
      if (dbl_indirect_table == UNUSED_SECTOR)
      {
        if(!free_map_allocate(1, &dbl_indirect_table)) {
          success = false;
          break;
        }
        inode_zero_sector(dbl_indirect_table, true);
        inode_set_dbl_indirect_sector_table(inode, dbl_indirect_table);
      }

      int trunc_cur_block = cur_block - N_DIRECT_PTRS - N_INDIRECT_PTRS;
      int dbl_indirect_index = trunc_cur_block / N_INDIRECT_PTRS;
      int indirect_index = trunc_cur_block % N_INDIRECT_PTRS;

      /* allocate indirect table if necessary */      
      block_sector_t indirect_table;
      if (indirect_index == UNUSED_SECTOR)
      {
        if (!free_map_allocate(1, &indirect_table)) {
          success = false;
          break;
        }
        inode_zero_sector(indirect_table, true);
        inode_set_sector_table_entry(dbl_indirect_table, dbl_indirect_index, indirect_table);
      } 
      else 
      {
        indirect_table = inode_get_sector_table_entry(dbl_indirect_table, dbl_indirect_index);
      }



      block_sector_t new_sector;
      if (!free_map_allocate(1, &new_sector)) {
        success = false;
        break;
      }

      inode_zero_sector(new_sector, false);
      inode_set_sector_table_entry(indirect_table, indirect_index, new_sector);

      
    }
  }

  if (success) 
    return new_length;
  else
    inode_free_sectors(inode,end_block,cur_block);

  return old_length;
}

/* zero-out a data sector */
void
inode_zero_sector(block_sector_t sector, bool meta)
{
  char zeros [BLOCK_SECTOR_SIZE];
  memset(zeros, 0, BLOCK_SECTOR_SIZE);
  cache_write(sector, FETCH_NONE, zeros, 0, BLOCK_SECTOR_SIZE, meta);
}


/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{

  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  off_t length = 0;
  off_t my_length = length;

  if (inode->deny_write_cnt)
    goto done;

  if (size == 0)
    goto done;

  int end_write_bytes = (offset + size);

  lock_acquire(&(inode->lock_file));
  
  length = inode_length(inode);

  if (end_write_bytes > length){
    
    while(inode->extending){
      cond_wait(&inode->ready_to_extend, &inode->lock_file);
    }

    length = inode_length(inode);
    if(end_write_bytes > length)
      inode->extending = true;
  }

  lock_release(&inode->lock_file);

  my_length = inode_extend(inode, length, end_write_bytes);
  

  while (size > 0) 
  {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector (inode, my_length, offset);
    block_sector_t next_sector_idx = byte_to_sector (inode, my_length, offset+BLOCK_SECTOR_SIZE);

    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = my_length - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;
    int chunk_size = size < min_left ? size : min_left;


    /* Number of bytes to actually write into this sector. */
    if (chunk_size <= 0)
      break;

    cache_write (sector_idx, next_sector_idx, buffer + bytes_written, 
                 sector_ofs, chunk_size, false);

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }

  done:
    
    if(my_length > length){
      lock_acquire(&inode->lock_file);
      ASSERT (inode->extending);
      inode->extending = false;
      inode_set_length(inode, my_length);
      cond_broadcast(&inode->ready_to_extend, &inode->lock_file);
      lock_release(&inode->lock_file);
    }

    return bytes_written;

}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

bool
inode_isdir(struct inode *inode)
{
  if (inode->sector == ROOT_DIR_SECTOR)
    return true;

  bool isdir;
  off_t sector_ofs = offsetof(struct inode_disk, is_dir);
  cache_read(inode->sector, FETCH_NONE, &isdir, sector_ofs, sizeof(bool),true); 
  return isdir; 
}

block_sector_t
inode_get_sector(struct inode *inode)
{
  return inode->sector;
}

int inode_get_count(struct inode *inode){
  return inode->open_cnt;
}

void inode_acquire_dir_lock(struct inode *inode){
  lock_acquire(&inode->lock_dir);
}

void inode_release_dir_lock(struct inode *inode){
  lock_release(&inode->lock_dir);
}

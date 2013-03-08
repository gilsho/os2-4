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
#include <stdio.h>


#if (DEBUG & DEBUG_INODE)
#define DEBUG_EXTEND
#define DEBUG_CREATE
#define DEBUG_OPEN
#define DEBUG_READ
#define DEBUG_WRITE
#endif

#ifdef DEBUG_EXTEND
#define PRINT_EXTEND(X) {printf("(inode-extend) "); printf(X);}
#define PRINT_EXTEND_2(X,Y) {printf("(inode-extend) "); printf(X,Y);}
#else
#define PRINT_EXTEND(X) do {} while(0)
#define PRINT_EXTEND_2(X,Y) do {} while(0)
#endif

#ifdef DEBUG_CREATE
#define PRINT_CREATE(X) {printf("(inode-create) "); printf(X);}
#define PRINT_CREATE_2(X,Y) {printf("(inode-create) "); printf(X,Y);}
#else
#define PRINT_CREATE(X) do {} while(0)
#define PRINT_CREATE_2(X,Y) do {} while(0)
#endif


#ifdef DEBUG_READ
#define PRINT_READ(X) {printf("(inode-read) "); printf(X);}
#define PRINT_READ_2(X,Y) {printf("(inode-read) "); printf(X,Y);}
#else
#define PRINT_READ(X) do {} while(0)
#define PRINT_READ_2(X,Y) do {} while(0)
#endif

#ifdef DEBUG_WRITE
#define PRINT_WRITE(X) {printf("(inode-write) "); printf(X);}
#define PRINT_WRITE_2(X,Y) {printf("(inode-write) "); printf(X,Y);}
#else
#define PRINT_WRITE(X) do {} while(0)
#define PRINT_WRITE_2(X,Y) do {} while(0)
#endif

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define N_DIRECT_PTRS 12
#define N_INDIRECT_PTRS (BLOCK_SECTOR_SIZE/sizeof(block_sector_t))
#define N_DBL_INDIRECT_PTRS (N_INDIRECT_PTRS * N_INDIRECT_PTRS)


/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    block_sector_t direct[N_DIRECT_PTRS];  /* first-order data sector. */
    block_sector_t indirect;
    block_sector_t dbl_indirect;
    off_t length;                                 /* File size in bytes. */
    unsigned magic;                               /* Magic number. */
    uint32_t unused[112];                         /* Not used. */
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
  };


void inode_free_sectors(struct inode_disk *disk_inode);
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
bool inode_extend(struct inode *inode, int new_length);
void inode_zero_sector(block_sector_t sector, bool meta);


off_t 
inode_length(const struct inode *inode) 
{
  size_t length;
  off_t sector_ofs = offsetof (struct inode_disk, length);
  cache_read (inode->sector, &length, sector_ofs, sizeof(size_t),true); 
  return length;
} 

void 
inode_set_length(struct inode *inode, int length)
{
  off_t sector_ofs = offsetof (struct inode_disk, length);
  cache_write (inode->sector, &length, sector_ofs, sizeof(size_t),true); 
}

block_sector_t 
inode_get_direct_sector(const struct inode *inode, int index)
{
  block_sector_t direct[N_DIRECT_PTRS];
  off_t sector_ofs = offsetof (struct inode_disk, direct);
  cache_read (inode->sector, &direct, sector_ofs, sizeof(block_sector_t)*N_DIRECT_PTRS,true); 
  return direct[index];
}

void
inode_set_direct_sector(const struct inode *inode, int index, block_sector_t direct)
{
  off_t sector_ofs = offsetof (struct inode_disk, direct) + index * sizeof(block_sector_t);
  cache_write (inode->sector, &direct, sector_ofs, sizeof(block_sector_t),true); 
}

block_sector_t 
inode_get_indirect_sector_table(const struct inode *inode)
{
  block_sector_t indirect;
  off_t sector_ofs = offsetof(struct inode_disk, indirect);
  cache_read(inode->sector, &indirect, sector_ofs, sizeof(block_sector_t),true);
  return indirect;
}

void
inode_set_indirect_sector_table(const struct inode *inode, block_sector_t indirect)
{
  off_t sector_ofs = offsetof(struct inode_disk, indirect);
  cache_write(inode->sector, &indirect, sector_ofs, sizeof(block_sector_t),true);
}

block_sector_t 
inode_get_dbl_indirect_sector_table(const struct inode *inode)
{
  block_sector_t dbl_indirect;
  off_t sector_ofs = offsetof(struct inode_disk,dbl_indirect);
  cache_read(inode->sector, &dbl_indirect, sector_ofs, sizeof(block_sector_t),true); 
  return dbl_indirect;
}

void
inode_set_dbl_indirect_sector_table(const struct inode *inode, block_sector_t dbl_indirect)
{
  off_t sector_ofs = offsetof(struct inode_disk,dbl_indirect);
  cache_write(inode->sector, &dbl_indirect, sector_ofs, sizeof(block_sector_t),true); 
}

block_sector_t 
inode_get_sector_table_entry(block_sector_t sector_table, int index)
{
  block_sector_t sector_entry;
  off_t sector_ofs =  index * sizeof(block_sector_t);
  cache_read (sector_table, &sector_entry, sector_ofs, sizeof(block_sector_t),true); 
  return sector_entry;
}

void
inode_set_sector_table_entry(block_sector_t sector_table, int index, block_sector_t sector_entry)
{ 
  off_t sector_ofs =  index * sizeof(block_sector_t);
  cache_write (sector_table, &sector_entry, sector_ofs, sizeof(block_sector_t),true); 
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);

  int block_num = pos/BLOCK_SECTOR_SIZE;

  off_t length = inode_length(inode);

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

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length)
{
  PRINT_CREATE_2("sector: %d\n", (int) sector);
  PRINT_CREATE_2("length: %d\n", (int) length);

  ASSERT (length >= 0);
  struct inode_disk *disk_inode = NULL;

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode == NULL)
    return false;

  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  /*size_t num_sectors = bytes_to_sectors (length);*/
  disk_inode->length = 0;
  disk_inode->magic = INODE_MAGIC;

  cache_write(sector, disk_inode, 0, BLOCK_SECTOR_SIZE, true);

  /* dummy i-node for file initialization */
  struct inode inode;
  inode.sector = sector;
  
  bool success = inode_extend(&inode, length);

  if (!success)
    inode_free_sectors(disk_inode);
  else
    inode_set_length(&inode, length);

  free (disk_inode);
    
  return success;
}


void
inode_free_sectors(struct inode_disk *disk_inode)
{
  size_t num_sectors = bytes_to_sectors (disk_inode->length);
  ASSERT(num_sectors < (int) N_DIRECT_PTRS + N_INDIRECT_PTRS + N_DBL_INDIRECT_PTRS);

  int cur_block;
  for (cur_block = 0; cur_block < (int)num_sectors; cur_block++)
  {
    /* clean up direct data sectors */
    if (cur_block < N_DIRECT_PTRS)
    {
      
      free_map_release (disk_inode->direct[cur_block], 1);
      disk_inode->direct[cur_block] = 0;
      
    }

    /* clean up indirect sectors, meta & data */
    else if (cur_block < (int)(N_DIRECT_PTRS + N_INDIRECT_PTRS))
    {

      block_sector_t data_sector;
      off_t sector_ofs = (cur_block - N_DIRECT_PTRS) * sizeof(block_sector_t);
      cache_read(disk_inode->indirect, &data_sector, 
                 sector_ofs, sizeof(block_sector_t),true);

      free_map_release (data_sector, 1);
    }

    /* clean up dbl indirect sectors, meta & data */
    else
    {

      block_sector_t indirect_sector;
      int dbl_indirect_idx = (cur_block - N_DIRECT_PTRS - N_INDIRECT_PTRS) / N_INDIRECT_PTRS;
      int indirect_idx = (cur_block - N_DIRECT_PTRS - N_INDIRECT_PTRS) % N_INDIRECT_PTRS;
    
      cache_read(disk_inode->dbl_indirect, &indirect_sector, 
                 dbl_indirect_idx * sizeof(block_sector_t), sizeof(block_sector_t),true);


      block_sector_t data_sector;
      cache_read(indirect_sector, &data_sector, 
                 indirect_idx * sizeof(block_sector_t), sizeof(block_sector_t),true);

      free_map_release (data_sector, 1);      

    }

  }

  /* free indirect table sector */
  if(disk_inode->indirect != 0){
    ASSERT(num_sectors > N_DIRECT_PTRS);
    free_map_release (disk_inode->indirect, 1);
  }
  
  if(disk_inode->dbl_indirect != 0){
    ASSERT(num_sectors > (int)(N_DIRECT_PTRS + N_INDIRECT_PTRS));

    int num_dbl_indirect_sectors = num_sectors - N_DIRECT_PTRS - N_INDIRECT_PTRS;

    int num_dbl_indirect_entries = num_dbl_indirect_sectors / N_INDIRECT_PTRS;

    if(num_dbl_indirect_sectors % N_INDIRECT_PTRS)
      num_dbl_indirect_entries++;

    int i;
    for(i = 0; i < num_dbl_indirect_entries; i++){
      block_sector_t indirect_sector;
      cache_read(disk_inode->dbl_indirect, &indirect_sector, 
                 i * sizeof(block_sector_t), sizeof(block_sector_t),true);

      ASSERT(indirect_sector > 1);
      free_map_release(indirect_sector, 1);
    }

    /* free dbl indirect table sector */
    free_map_release (disk_inode->dbl_indirect, 1);
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

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  /* WE DONT NEED TO DO THIS??? */
  /*block_read (fs_device, inode->sector, &inode->data);*/
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

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          /* Should this be on stack? Malloc? */
          struct inode_disk d_inode;
          cache_read(inode->sector, &d_inode, 0, sizeof(struct inode_disk), true);
          inode_free_sectors(&d_inode);

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

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);

      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      PRINT_READ_2("sectord_idx: %d\n", (int) sector_idx);
      PRINT_READ_2("read_size: %d\n", size);
      PRINT_READ_2("offset: %d\n",sector_ofs);
      PRINT_READ_2("chunk_size: %d\n", chunk_size);

      cache_read(sector_idx, buffer + bytes_read, sector_ofs, 
                  chunk_size, false);
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }

  return bytes_read;
}

bool 
inode_extend(struct inode *inode, int new_length)
{
  ASSERT(new_length >= 0);
  if (new_length == 0)
    return true;

  int length = (int) inode_length(inode);

  if (new_length <= length)
    return true;

  /* At this point, we must allocate more sectors */
  block_sector_t new_sector;
  if (length == 0)
  {
    /* first sector for an empty file */
    if (!free_map_allocate (1,&new_sector))
      return false;

    inode_zero_sector(new_sector, true);
    inode_set_direct_sector(inode, 0, new_sector);
  }

  int end_block = length > 0 ? (length-1) / BLOCK_SECTOR_SIZE : 0;
  int end_write_block = (new_length-1) / BLOCK_SECTOR_SIZE;

  bool success = true;
  int cur_block;
  for (cur_block = end_block + 1; cur_block <= end_write_block; cur_block++)
  {
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

    else if (cur_block < (int)(N_INDIRECT_PTRS + N_DIRECT_PTRS))
    {
      block_sector_t indirect_table = inode_get_indirect_sector_table(inode);
      if (indirect_table == 0)
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

    else if (cur_block <  (int) (N_DBL_INDIRECT_PTRS + N_INDIRECT_PTRS + N_DIRECT_PTRS))
    {
      /* allocate dbl_indirect sector if necessary */
      block_sector_t dbl_indirect_table = inode_get_dbl_indirect_sector_table(inode);
      if (dbl_indirect_table == 0)
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
      
      block_sector_t indirect_table;
      /* allocate indirect sector if necessary */
      if (indirect_index == 0)
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

  return success;
}

/* zero-out a data sector */
void
inode_zero_sector(block_sector_t sector, bool meta)
{
  char zeros [BLOCK_SECTOR_SIZE];
  memset(zeros, 0, BLOCK_SECTOR_SIZE);
  cache_write(sector, zeros, 0, BLOCK_SECTOR_SIZE, meta);
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

  if (inode->deny_write_cnt)
    return 0;

  if (size == 0)
    return 0;

  int end_write_bytes = (offset + size);

  if (!inode_extend(inode, end_write_bytes))
    return 0;
  else
    inode_set_length(inode, end_write_bytes);

  while (size > 0) 
  {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector (inode, offset);
    PRINT_WRITE_2("sector_idx: %d\n", sector_idx);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length (inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;
    int chunk_size = size < min_left ? size : min_left;


    PRINT_WRITE_2("sector_idx: %d\n", sector_idx);
    PRINT_WRITE_2("offset: %d\n", sector_ofs);
    PRINT_WRITE_2("chunk_size: %d\n", chunk_size);

    /* Number of bytes to actually write into this sector. */
    if (chunk_size <= 0)
      break;

    cache_write (sector_idx, buffer + bytes_written, 
                 sector_ofs, chunk_size, false);

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }

  PRINT_WRITE_2("bytes_written: %d\n", bytes_written);

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



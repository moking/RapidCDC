/*
 * =====================================================================================
 *
 *       Filename:  fsc.h
 *
 *    Description:  fixed size chunking
 *
 *        Version:  1.0
 *        Created:  10/14/2018 04:36:15 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  fan ni 
 *   Organization:  
 *
 * =====================================================================================
 */

#ifndef CHUNKER_FSC_H_H
#define CHUNKER_FSC_H_H
#include "common.h"

static int regular_chunking_fsc(struct file_struct *fs){
  uint64_t n_bytes_left;
  uint64_t offset = 0;
  uint32_t hash = 0;
  uint8_t *str = (uint8_t *)fs->map;
  uint64_t local_offset = 0;
  uint64_t last_offset = 0;
  struct chunk_boundary cb;
  uint32_t avg_size= 1<< break_mask_bit;


  int tid = fs_idx(fs);
  reset_chunk_boundary_list(tid);

  while( offset < fs->test_length ){
    if ( fs->test_length < avg_size + offset+min_chunksize){
      offset = fs->test_length;
    }else{
      offset = offset+avg_size;
    }
    cb.left = last_offset;
    cb.right = offset;
    insert_chunk_boundary(tid, &cb);
    dedup_stats.total_chunks++;
    dedup_stats.total_size += cb.right-cb.left;
    last_offset = offset;
  }

  return 0;
}

#endif

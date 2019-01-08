#ifndef CHUNKER_GEAR_H_H
#define CHUNKER_GEAR_H_H
#include "common.h"
#include "fsc.h"

	//*x = (*x >> 8) ^ ((*x ^ c) & 0xff);
static inline uint32_t GEAR_HASHLEN() { return break_mask_bit;}
//static inline void doGear_serial(uint32_t c, uint32_t* x)
#define doGear_serial(c, x)\
{\
	*x = ((*x<<1) + crct[c&0xff])&break_mask; \
  per_thread_stats[tid].num_rollings++;\
}


static int regular_chunking_cdc_gear(struct file_struct *fs){
  uint64_t offset = 0;
  uint32_t hash = 0;
  uint8_t *str = (uint8_t *)fs->map;
  uint64_t local_offset = 0;
  uint64_t last_offset = 0;
  struct chunk_boundary cb;


  int tid = fs_idx(fs);

  //printf("Thread %d chunking\n", tid);

  reset_chunk_boundary_list(tid);


  if(fs->length <= GEAR_HASHLEN() || fs->length< 2* min_chunksize) {
		assert(0);
    return 0;
  }

  while( offset < fs->test_length ){
		doGear_serial(str[offset], &hash);
		offset++;
		
		if ( offset-last_offset >= min_chunksize || offset == fs->test_length) {
      //determine a chunk boundary, chunk range [ last_offset, offset)
			if((hash == magic_number) || offset-last_offset>=max_chunksize || offset == fs->test_length){
last_chunk:
        cb.left = last_offset;
        cb.right = offset;
        insert_chunk_boundary(tid, &cb);
        per_thread_stats[tid].total_chunks++;
        per_thread_stats[tid].total_size += cb.right-cb.left;
				//chunk_id++;
        last_offset = offset;

				if (fs->test_length == offset){
					break;
				}
				if ( fs->test_length < 2*min_chunksize+offset){
					offset = fs->test_length;
					goto last_chunk;
				}else{
					offset+=min_chunksize-GEAR_HASHLEN();
					hash = 0;
				}
      }
    }
  } // while

  //printf("chunk id: %lu\n", chunk_id);
  return 0;
}

// fast forward with fp check
// fast_skip = 1
int chunking_phase_one_gear_fast(struct file_struct *fs){
  uint64_t offset = 0, local_offset = 0;
  uint32_t hash = 0;
  uint8_t *str = (uint8_t *)fs->map;
  uint64_t last_offset = 0;
  uint8_t hash_fp[SHA_DIGEST_LENGTH];
  struct chunk_boundary cb;
  struct fp_entry_st *fp = NULL, *last_recipe_fp = NULL, *fast_fp = NULL;
  int skipped = 0, next_size_idx = 0;

  int tid = fs_idx(fs);
  int next_size = 0;

  assert(fast_skip == 1);
  reset_chunk_boundary_list(tid);

  if(fs->length <= GEAR_HASHLEN() || fs->length< 2*min_chunksize) {
		assert(0);
    return 0;
  }

  while( offset < fs->test_length ){
      doGear_serial(str[offset], &hash);
      local_offset ++;
      offset++;
			if (skipped){
				if(local_offset == GEAR_HASHLEN()){
					if((hash != magic_number) && offset-last_offset < max_chunksize && offset < fs->test_length){
fast_detect_fail:
						offset = last_offset;

            if (next_size_idx < list_length-1){
              next_size_idx++;
              goto fetch_next_size;
            }

            local_offset = 0; 
            hash = 0;
            offset+=min_chunksize-GEAR_HASHLEN();
						per_thread_stats[tid].fast_miss_chunks++;
            skipped = 0;
						continue;
					}else{
						cb.left = last_offset;
						cb.right = offset;
						bzero(hash_fp, SHA_DIGEST_LENGTH);
						compute_fingerprint(fs, &cb, hash_fp);
            lock_hash_slot(hash_fp);
						fast_fp = lookup_fp(hash_fp);
            unlock_hash_slot(hash_fp);
						if (fast_fp == NULL){
							per_thread_stats[tid].fast_false_hit_chunks++;
							goto fast_detect_fail;
						}
						else{ // fast detect succeed
							per_thread_stats[tid].fast_hit_chunks++;
							per_thread_stats[tid].total_chunks++;
							per_thread_stats[tid].total_size += cb.right-cb.left;
							last_offset = offset;

              fp =fast_fp;
							goto boundary_hit_in_fast;
						}
					}
				}
				continue;
			}

			if ( offset-last_offset >= min_chunksize || offset == fs->test_length) {
				//determine a chunk boundary, chunk range [ last_offset, offset)
      if(((hash ) == magic_number) || offset-last_offset>=max_chunksize||offset == fs->test_length){
last_chunk_fast:
				cb.left = last_offset;
				cb.right = offset;

				bzero(hash_fp, SHA_DIGEST_LENGTH);
				compute_fingerprint(fs, &cb, hash_fp);
				per_thread_stats[tid].total_chunks++;
				per_thread_stats[tid].total_size += cb.right-cb.left;
				last_offset = offset;
        lock_hash_slot(hash_fp);
				fp = lookup_fp(hash_fp);
				if (fp == NULL){
          fp = insert_fp(hash_fp);
          unlock_hash_slot(hash_fp);

          if(last_recipe_fp)
            record_next_size(last_recipe_fp, cb.right-cb.left,0);
          last_recipe_fp = fp;
          next_size_idx = 0;

          if (do_io)
            do_write(tid, dump_fd, fs->map, &cb);

          per_thread_stats[tid].uniq_size+= cb.right-cb.left;
					per_thread_stats[tid].uniq_chunks ++;
         if ( reach_file_end(fs, offset)){
            break;
          }
          if (fs->test_length-offset < 2*min_chunksize){
            offset = fs->test_length;
            goto last_chunk_fast;
          }
          offset+=min_chunksize-GEAR_HASHLEN();
					skipped = 0;
				} else{
          unlock_hash_slot(hash_fp);
boundary_hit_in_fast:
          if ( reach_file_end(fs, offset)){
            break;
          }
          if (fs->test_length-offset < 2*min_chunksize){
            offset = fs->test_length;
            goto last_chunk_fast;
          }

          if (last_recipe_fp ){
            if (skipped && next_size_idx > 0)
              record_next_size(last_recipe_fp, cb.right-cb.left);
            if(skipped == 0)
              record_next_size(last_recipe_fp, cb.right-cb.left);
          }
          last_recipe_fp = fp;
          next_size_idx = 0;

fetch_next_size:
          next_size = next_chunk_size(last_recipe_fp, next_size_idx); 
          if (next_size == 0){
						offset+=min_chunksize-GEAR_HASHLEN();
            next_size_idx = 0;
						skipped = 0;
          }else if (offset+ next_size > fs->test_length){
            next_size_idx++;
            goto fetch_next_size;
					}else{ // fast jump
						offset += next_size-GEAR_HASHLEN();
						skipped = 1;
					}
				}
				local_offset = 0;
				hash = 0;
			}
    } // size >= min_chunksize-1
  } // while
      
  if (do_io)
		sync_data_to_disk(tid);
  return 0;
}

// fast forward with fp check
// fast_skip = 2
int chunking_phase_one_gear_super_fast(struct file_struct *fs){
  uint64_t offset = 0;
  uint32_t hash = 0;
  uint8_t *str = (uint8_t *)fs->map;
  uint64_t local_offset = 0;
  uint64_t last_offset = 0;
  uint8_t hash_fp[SHA_DIGEST_LENGTH];
  struct chunk_boundary cb;
  struct fp_entry_st *fp = NULL;
  struct fp_entry_st *last_recipe_fp=NULL;
  int skipped = 0, next_size_idx = 0, last_size_idx = 0;
  int next_size, tmp;
  uint8_t mark;

  int tid = fs_idx(fs);

  //printf("Thread %d chunking\n", tid);

  assert(fast_skip == 2);
  reset_chunk_boundary_list(tid);

  if(fs->length <= GEAR_HASHLEN() || fs->length< 2*min_chunksize) {
		assert(0);
    return 0;
  }

  while( offset < fs->test_length ){
      doGear_serial(str[offset], &hash);
      offset++;
      local_offset ++;
			if (skipped){
				if (local_offset == GEAR_HASHLEN()){
					if((hash  != magic_number) && offset-last_offset < max_chunksize 
							&& offset != fs->test_length){
						per_thread_stats[tid].fast_miss_chunks++;
fast_detect_fail:
						offset = last_offset;
						local_offset = 0; 
						hash = 0;

            if (next_size_idx == list_length-1){
              offset+=min_chunksize-GEAR_HASHLEN();
              skipped = 0;
              continue;
            }else{
              next_size_idx++;
              goto fetch_next_size;
            }
					}else{
						per_thread_stats[tid].fast_hit_chunks++;
						goto regular_hit_chunk;
					}
				}
				continue;
			}

		if ( offset-last_offset >= min_chunksize || offset == fs->test_length) {
      //determine a chunk boundary, chunk range [ last_offset, offset)
			if(((hash ) == magic_number) || offset-last_offset>=max_chunksize||offset == fs->test_length){
last_chunk_super_fast:
regular_hit_chunk:
        cb.left = last_offset;
        cb.right = offset;
        //size_list[chunk_id] = cb.right - cb.left;

        if (last_recipe_fp){
          next_size = cb.right-cb.left;
          if (jump_with_mark_test){
            uint32_t head = *(str+cb.right-1);
            next_size = (head<<24)+next_size;
          }
          if (skipped && next_size_idx > 0)
            record_next_size(last_recipe_fp, next_size, 0);
          // should we record
          if (skipped == 0)
            record_next_size(last_recipe_fp, next_size, 0);
        }
     //insert_chunk_boundary(tid, &cb);

        bzero(hash_fp, SHA_DIGEST_LENGTH);
        compute_fingerprint(fs, &cb, hash_fp);
        per_thread_stats[tid].total_chunks++;
        per_thread_stats[tid].total_size += cb.right-cb.left;
				last_offset = offset;
        lock_hash_slot(hash_fp);
        fp = lookup_fp(hash_fp);
        if (fp == NULL){
          fp = insert_fp(hash_fp);
          unlock_hash_slot(hash_fp);

          //if(last_recipe_fp){
            //next_size = cb.right-cb.left;
            //if (jump_with_mark_test){
              //uint32_t head = *(str+cb.right-1);
              //next_size = (head<<24)+next_size;
            //}
            //record_next_size(last_recipe_fp, next_size, 0);
          //}

					last_recipe_fp = fp;
          last_size_idx = 0;
          next_size_idx = 0;



          if (do_io)
            do_write(tid, dump_fd, fs->map, &cb);

          per_thread_stats[tid].uniq_size+= cb.right-cb.left;
          per_thread_stats[tid].uniq_chunks ++;

					if (reach_file_end(fs, offset)){
						break;
					}
					if ( fs->test_length-offset < 2*min_chunksize){
						offset = fs->test_length;
						goto last_chunk_super_fast;
					}

          offset+=min_chunksize-GEAR_HASHLEN();
					skipped = 0;
        } else{  // hit
          unlock_hash_slot(hash_fp);
					last_recipe_fp = fp;
          last_size_idx = 0;
          next_size_idx = 0;

          if ( reach_file_end(fs, offset)){
            break;
          }
          if ( fs->test_length-offset < 2*min_chunksize){
            offset = fs->test_length;
            goto last_chunk_super_fast;
          } 

fetch_next_size:
          tmp = next_chunk_size(fp, next_size_idx); 
					next_size = tmp & 0xffffff;
					mark = tmp >> 24;
          if (next_size == 0){
						offset+=min_chunksize-HASHLEN;
						skipped = 0;

            last_recipe_fp = fp;
            last_size_idx = list_length;
            next_size_idx = 0;
          }else if (offset+ next_size > fs->test_length){
						offset+=min_chunksize-GEAR_HASHLEN();
						skipped = 0;

            //give up, can try others
            last_recipe_fp = fp;
            last_size_idx = list_length;
            next_size_idx = 0;
          }else{ // fast jump
						//last_recipe_fp = fp;
            //last_size_idx = next_size_idx;
            //next_size_idx = 0;

						if (skipped && blind_jump)
							per_thread_stats[tid].fast_hit_chunks++;
						else
							skipped = 1;
						if (blind_jump){
							offset += next_size;
							goto regular_hit_chunk;
						} else{
							if (jump_with_mark_test){
								if	(mark == *(str + offset + next_size -1)){
									per_thread_stats[tid].fast_hit_chunks++;
									offset += next_size;
									goto regular_hit_chunk;
								}else{
                  if (next_size_idx < list_length-1){
                    next_size_idx++;
                    goto fetch_next_size;
                  }
									offset += min_chunksize-GEAR_HASHLEN();
									per_thread_stats[tid].fast_miss_chunks++;
									skipped = 0;
								}
							}else
								offset += next_size-GEAR_HASHLEN();
						}
					}
        }
        hash = 0;
				local_offset = 0;
      }
    } // size >= min_chunksize-1
  } // while
  
  if (do_io)
    sync_data_to_disk(tid);
      
  return 0;
}



int chunking_phase_one_serial_gear(struct file_struct *fs){
  uint64_t offset = 0;
  uint32_t hash = 0;
  uint8_t *str = (uint8_t *)fs->map;
  uint64_t local_offset = 0;
  uint64_t last_offset = 0;
  uint8_t hash_fp[SHA_DIGEST_LENGTH];
  struct chunk_boundary cb;
  struct fp_entry_st *fp = NULL;
  int skipped = 0;
  uint64_t s_ns, e_ns;

  int tid = fs_idx(fs);

  switch(fast_skip){
    case 0: //regular 
      //printf("Decoupling chunking and deduplication\n");
      s_ns = time_nsec();
      regular_chunking_cdc_gear(fs);
      e_ns = time_nsec();
      per_thread_stats[tid].regular_ctime += e_ns - s_ns;
      s_ns = time_nsec();
      regular_deduplication(fs);
      e_ns = time_nsec();
      per_thread_stats[tid].regular_dtime += e_ns - s_ns;
      return 0;
    case 1: // fast forward with fp check
      s_ns = time_nsec();
      chunking_phase_one_gear_fast(fs);
      e_ns = time_nsec();
      per_thread_stats[tid].fast_cdtime += e_ns - s_ns;
      return 0;
    case 2: // fast forward without fp check
      s_ns = time_nsec();
      chunking_phase_one_gear_super_fast(fs);
      e_ns = time_nsec();
      per_thread_stats[tid].fast_cdtime += e_ns - s_ns;
      s_ns = time_nsec();
      //regular_deduplication(fs);
      //e_ns = time_nsec();
      //per_thread_stats[tid].regular_dtime += e_ns - s_ns;
      return 0;
    case 3: //regular FSC
      s_ns = time_nsec();
      regular_chunking_fsc(fs);
      e_ns = time_nsec();
      per_thread_stats[tid].regular_ctime += e_ns - s_ns;
      s_ns = time_nsec();
      regular_deduplication(fs);
      e_ns = time_nsec();
      per_thread_stats[tid].regular_dtime += e_ns - s_ns;
      return 0;
		case TRACE_MODE:
      regular_chunking_cdc_gear(fs);
			generate_microbench(fs);
			break;


    default:
      assert(0);
  }
      
  return 0;
}

#endif

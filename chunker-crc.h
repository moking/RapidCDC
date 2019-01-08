#ifndef CHUNKER_CRC_H_H
#define CHUNKER_CRC_H_H
#include "common.h"

#include "fsc.h"

#define doCrc_serial_crc(c, x) \
{\
	*x = (*x >> 8) ^ crct[(*x ^ c) & 0xff];\
  per_thread_stats[tid].num_rollings++; \
}

//static inline void doCrc_serial_crc(uint32_t c, uint32_t* x)
//{
	//*x = (*x >> 8) ^ crct[(*x ^ c) & 0xff];
  //per_thread_stats[tid].num_rollings++;
//}


static int regular_chunking_cdc(struct file_struct *fs){
	uint64_t offset = 0;
	uint32_t hash = 0;
	uint8_t *str = (uint8_t *)fs->map;
	uint64_t local_offset = 0;
	uint64_t last_offset = 0;
	struct chunk_boundary cb;
	uint64_t mask = break_mask;

  int tid = fs_idx(fs);

  //printf("Thread %d chunking\n", tid);

	reset_chunk_boundary_list(tid);

	// too small file
	if(fs->length <= HASHLEN || fs->length< 2*min_chunksize) {
		cb.left = 0;
		cb.right = fs->length;
		insert_chunk_boundary(tid, &cb);
		return 0;
	}

	while( offset < fs->test_length ){
		if(local_offset < HASHLEN){
			doCrc_serial_crc(str[offset], &hash);
			local_offset ++;
			offset++;
		}else{
			// first offset to reach here is HASHLEN
			hash^=crcu[str[offset-HASHLEN]];
			doCrc_serial_crc(str[offset], &hash);
			offset++;
		}
		// skip mini chunk size
		if ( offset-last_offset >= min_chunksize || offset == fs->test_length) {
			//determine a chunk boundary, chunk range [ last_offset, offset)
			if(((hash & mask) == magic_number) || offset-last_offset>=max_chunksize || offset == fs->test_length){
last_chunk:
				cb.left = last_offset;
				cb.right = offset;
				insert_chunk_boundary(tid, &cb);
				per_thread_stats[tid].total_chunks++;
				per_thread_stats[tid].total_size += cb.right-cb.left;
				last_offset = offset;
				if (fs->test_length == offset){
					break;
				}
				if ( fs->test_length < 2*min_chunksize+offset){
					offset = fs->test_length;
					goto last_chunk;
				}else{
					offset+=min_chunksize-HASHLEN;
					local_offset = 0;
					hash = 0;
				}
			}
		}
	} // while

	//printf("file size: %lu offset %lu cid %lu\n", fs->test_length, offset, chunk_id);

  //printf("Thread %d chunking complete\n", tid);
	return 0;
}

static int regular_deduplication(struct file_struct *fs){
	uint8_t hash_fp[SHA_DIGEST_LENGTH];
	struct chunk_boundary cb;
	struct fp_entry_st *fp = NULL;
	static uint64_t cid = 0;
	int seq_len = 0;
	uint64_t last_dedup_cid = 0;

  int tid = fs_idx(fs);
  //printf("Thread %d Deduplication\n", tid);

	reset_chunk_idx_in_file(tid);
	bzero(hash_fp, SHA_DIGEST_LENGTH);
  while(next_chunk_boundary(tid, &cb)){
    compute_fingerprint(fs, &cb, hash_fp);
    lock_hash_slot(hash_fp);
    fp = lookup_fp(hash_fp);
		//if (enable_dedup_bitmap)
			//update_dedup_bitmap(fp != NULL);
    if (fp){
      unlock_hash_slot(hash_fp);
			if (profile){
				if(seq_len == 0){
					seq_len = 1;
				}else{
					if (fp->chunk_id == last_dedup_cid+1){
						seq_len++;
					}else {
						update_chunk_sequence_list(seq_len);
						seq_len = 1;
					}
				}
				last_dedup_cid = fp->chunk_id;
			}
    }else{
      insert_fp(hash_fp, cid++);
      unlock_hash_slot(hash_fp);
			if(profile){
				if (seq_len > 0){
					update_chunk_sequence_list(seq_len);
					seq_len = 0;
					last_dedup_cid = 0;
				}
			}
      per_thread_stats[tid].uniq_size+= cb.right-cb.left;
      per_thread_stats[tid].uniq_chunks ++;
      if (do_io)
        do_write(tid, dump_fd, fs->map, &cb);
    }
  }

  if (do_io)
		sync_data_to_disk(tid);

	if (profile && seq_len > 0)
		update_chunk_sequence_list(seq_len);

  //printf("Thread %d Deduplication\n", tid);
  return 0;
}

static int collect_similarity(struct file_struct *fs){
	uint8_t hash_fp[SHA_DIGEST_LENGTH];
	struct chunk_boundary cb;
	struct fp_entry_st *fp = NULL;
	static uint64_t cid = 0;
	int seq_len = 0, uniq_seq_len = 0;
	uint64_t last_dedup_cid = 0;

  int tid = fs_idx(fs);

  printf("Thread %d chunking\n", tid);
	reset_chunk_idx_in_file(tid);
	bzero(hash_fp, SHA_DIGEST_LENGTH);
  while(next_chunk_boundary(tid, &cb)){
    compute_fingerprint(fs, &cb, hash_fp);
    fp = lookup_fp(hash_fp);
    if (fp){
			if (sm_profile){
				if (uniq_seq_len >0){
					assert(seq_len == 0);
					printf("LEN %d UNIQ SEQ END\n", uniq_seq_len);
					uniq_seq_len = 0;
				}
				if (seq_len == 0)
					printf("SEQ START ");
				seq_len++;
				print_fingperint(hash_fp, SHA_DIGEST_LENGTH);
			}
		}else{
			if(sm_profile){
				if (seq_len > 0){
					assert(uniq_seq_len == 0);
					printf("LEN %d SEQ END\n", seq_len);
					seq_len = 0;
				}
					if (uniq_seq_len == 0)
						printf("UNIQ SEQ START ");
					uniq_seq_len++;
					print_fingperint(hash_fp, SHA_DIGEST_LENGTH);
				}
				insert_fp(hash_fp, cid++);
			}
		}

	if (seq_len > 0){
		printf("LEN %d SEQ END\n", seq_len);
		seq_len = 0;
	}

	if (uniq_seq_len > 0){
		printf("LEN %d UNIQ SEQ END\n", uniq_seq_len);
		uniq_seq_len = 0;
	}

  return 0;
}


// fast forward with fp check
// fast_skip = 1
int chunking_phase_one_crc_fast(struct file_struct *fs){
  uint64_t offset = 0;
  uint32_t hash = 0;
  uint8_t *str = (uint8_t *)fs->map;
  uint64_t local_offset = 0;
  uint64_t last_offset = 0;
  uint8_t hash_fp[SHA_DIGEST_LENGTH];
  struct chunk_boundary cb;
  struct fp_entry_st *fp = NULL, *last_recipe_fp = NULL, *fast_fp = NULL;
  int skipped = 0, next_size_idx = 0;
	uint64_t mask = break_mask;

  int tid = fs_idx(fs);
  int next_size = 0;

  assert(fast_skip == 1);
  reset_chunk_boundary_list(tid);

  if(fs->length <= HASHLEN || fs->length< 2*min_chunksize) {
		assert(0);
    return 0;
  }

  while( offset < fs->test_length ){
		if(local_offset < HASHLEN){
			doCrc_serial_crc(str[offset], &hash);
			local_offset ++;
			offset++;
			if (skipped){
				if (local_offset == HASHLEN){
					if(((hash & mask) != magic_number) && offset-last_offset < max_chunksize 
							&& offset != fs->test_length){
fast_detect_fail:
						offset = last_offset;

            if (next_size_idx < list_length-1){
              next_size_idx++;
              goto fetch_next_size;
            }

            local_offset = 0; 
            hash = 0;
            offset+=min_chunksize-HASHLEN;
            skipped = 0;
						per_thread_stats[tid].fast_miss_chunks++;
						if (lru_enabled)
							lru_hits[list_length]++;
						continue;
					}else{ // rolling window hit
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

              fp = fast_fp;
							if (lru_enabled)
								lru_hits[next_size_idx] ++;
							goto boundary_hit_in_fast;
						}
					}
				}
				continue;
			}
		}else{
			// first offset to reach here is HASHLEN
        hash^=crcu[str[offset-HASHLEN]];
        doCrc_serial_crc(str[offset], &hash);
        offset++;
    }

    if ( offset-last_offset >= min_chunksize || offset == fs->test_length) {
      //determine a chunk boundary, chunk range [ last_offset, offset)
      if(((hash & break_mask) == magic_number) || offset-last_offset>=max_chunksize||offset == fs->test_length){
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
          
					//last_recipe_fp = NULL;
          //*****should we record size here?
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
          offset+=min_chunksize-HASHLEN;
					skipped = 0;
        } else{
          // should we unlock here or after LRU ??
          unlock_hash_slot(hash_fp);
boundary_hit_in_fast:
          if ( reach_file_end(fs, offset)){
            break;
          }
          if (fs->test_length-offset < 2*min_chunksize){
            offset = fs->test_length;
            goto last_chunk_fast;
          }
          //printf("Real chunk size %d for duplicate\n", cb.right-cb.left);
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
          //printf("Fetch %lu next size %d idx %d\n", *(uint64_t*)last_recipe_fp->hash, next_size, next_size_idx);
          if (next_size == 0){
            // only happen for the A-A-
						offset+=min_chunksize-HASHLEN;
            next_size_idx = 0;
            skipped = 0;
						if (lru_enabled)
							lru_hits[list_length]++;
          }else if (offset+ next_size > fs->test_length){
            next_size_idx++;
            goto fetch_next_size;
					}else{ // fast jump
						offset += next_size-HASHLEN;
						skipped = 1;
					}
        }
				local_offset = 0;
        hash = 0;
      }
    } // size >= min_chunksize-1
  } // while

  //printf("file size: %lu\n", offset);
  if (do_io)
		sync_data_to_disk(tid);
      
  return 0;
}

// fast forward with fp check
// fast_skip = 2
int chunking_phase_one_crc_super_fast(struct file_struct *fs){
  uint64_t offset = 0;
  uint32_t hash = 0;
  uint8_t *str = (uint8_t *)fs->map;
  uint64_t local_offset = 0;
  uint64_t last_offset = 0;
  uint8_t hash_fp[SHA_DIGEST_LENGTH];
  struct chunk_boundary cb;
  struct fp_entry_st *fp = NULL, * last_recipe_fp=NULL;
  int skipped = 0, next_size_idx = 0;
	uint64_t mask = break_mask;
  int next_size, tmp;
  uint8_t mark;

  int tid = fs_idx(fs);

  assert(fast_skip == 2);
  reset_chunk_boundary_list(tid);

  if(fs->length <= HASHLEN || fs->length< 2*min_chunksize) {
		assert(0);
    return 0;
  }

	while( offset < fs->test_length ){
		if(local_offset < HASHLEN){
			doCrc_serial_crc(str[offset], &hash);
			local_offset ++;
			offset++;
			if (skipped){
				if (local_offset == HASHLEN){
					if(((hash & mask) != magic_number) && offset-last_offset < max_chunksize 
							&& offset != fs->test_length){
						per_thread_stats[tid].fast_miss_chunks++;
fast_detect_fail:
						offset = last_offset;
						local_offset = 0; 
						hash = 0;

            if (next_size_idx == list_length-1){
              offset+=min_chunksize-HASHLEN;
							if (lru_enabled)
								lru_hits[list_length]++;
              skipped = 0;
              continue;
            }else{
              next_size_idx++;
              goto fetch_next_size;
            }
						//only blind_jump = 0 can go here
					}else{
						per_thread_stats[tid].fast_hit_chunks++;
						goto regular_hit_chunk;
					}
				}
				continue;
			}
		}else{
			// first offset to reach here is HASHLEN
			hash^=crcu[str[offset-HASHLEN]];
			doCrc_serial_crc(str[offset], &hash);
			offset++;
		}

		if ( offset-last_offset >= min_chunksize || offset == fs->test_length) {
			//determine a chunk boundary, chunk range [ last_offset, offset)
			if(((hash & break_mask) == magic_number) || offset-last_offset>=max_chunksize||offset == fs->test_length){
last_chunk_super_fast:
regular_hit_chunk:
				cb.left = last_offset;
				cb.right = offset;

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
          else
						if (lru_enabled)
							lru_hits[next_size_idx] ++;
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
					offset+=min_chunksize-HASHLEN;
					skipped = 0;
				} else{ // hit
          unlock_hash_slot(hash_fp);
					last_recipe_fp = fp;
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
            next_size_idx = 0;
						if (lru_enabled)
							lru_hits[list_length]++;
          }else if (offset+ next_size > fs->test_length){
						offset+=min_chunksize-HASHLEN;
						skipped = 0;
            //give up, can try others
            last_recipe_fp = fp;
            next_size_idx++;
					}else{ // fast jump
						//last_recipe_fp = fp;
            //last_size_idx = next_size_idx;
            //next_size_idx = 0;

						if (skipped && blind_jump){
							per_thread_stats[tid].fast_hit_chunks++;
						}
						else{
							skipped = 1;
						}
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
									offset+=min_chunksize-HASHLEN;
									per_thread_stats[tid].fast_miss_chunks++;
									skipped = 0;
								}
							}else
								offset += next_size - HASHLEN;
						}
					}
				}
				local_offset = 0;
				hash = 0;
			}
		} // size >= min_chunksize-1
	} // while

  if (do_io)
		sync_data_to_disk(tid);
	//printf("file size: %lu\n", offset);
	return 0;
}


int chunking_phase_one_serial_crc(struct file_struct *fs){
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
      regular_chunking_cdc(fs);
      e_ns = time_nsec();
      per_thread_stats[tid].regular_ctime += e_ns - s_ns;
      s_ns = time_nsec();
      regular_deduplication(fs);
      e_ns = time_nsec();
      per_thread_stats[tid].regular_dtime += e_ns - s_ns;
      return 0;
    case 1: // fast forward with fp check
      s_ns = time_nsec();
      chunking_phase_one_crc_fast(fs);
      e_ns = time_nsec();
      per_thread_stats[tid].fast_cdtime += e_ns - s_ns;
      return 0;
    case 2: // fast forward without fp check
      s_ns = time_nsec();
      chunking_phase_one_crc_super_fast(fs);
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
      regular_chunking_cdc(fs);
			generate_microbench(fs);
			break;
		case SEQ_TRACE_MODE:
      regular_chunking_cdc(fs);
			collect_similarity(fs);
			break;
    default:
      assert(0);
  }
      
  return 0;
}

#endif

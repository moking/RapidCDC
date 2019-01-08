#include "common.h"



static int start_exec = 0;
//char fname_ab[256];

void *worker_thread(void *ptr){
  char path[256];
  int tid = *(int *)ptr;
  char *fname;
  //printf("Thread %d start execute!\n", tid);
  strcpy(path, dir);
  fname = path+strlen(dir);
  start_exec = 1;
  while(next_file(fname)){
    fs_set[tid].fname = path;
    if (init_fs(&fs_set[tid]))
      continue;
    //printf("Thread %d processing %s\n", tid, fs_set[tid].fname);
    run_cdc_with_timer(&fs_set[tid]);
    finialize_fs(&fs_set[tid]);
  }

  //printf("Thread %d exit execute!\n", tid);
  return NULL;
}

int main(int argc, char *argv[]){
  uint64_t start, end, ptime = 0;
  uint64_t start_s, end_s, stime = 0;
  int n = 0;
  char hname[64];
  uint64_t max_file_size=1024*1024*1024;

  pthread_t *threads;

  if ( parse_args(argc, argv) != 0)
    return 0;

  create_per_thread_stats(num_threads);

  init_chunk_size_dist(min_chunksize, max_chunksize, 1024);
  init_fp_pool(1*1024*1024, SHA_DIGEST_LENGTH);
  init_chunk_boundary_list();

  if (do_io){
    dump_fd = create_dump_file(dump_dir, dump_fname);
    assert(dump_fd > 0);
  }
  
	if (profile)
		init_chunk_sequence_list(sequence_gaps);

  threads = (pthread_t *)calloc(sizeof(pthread_t)*num_threads, 1);
  assert(threads);
  fs_set = (struct file_struct*) calloc(sizeof(struct file_struct ) * num_threads, 1);
  assert(fs_set);

  if (dir && !is_trace_mode()){
    collect_files(dir);
    init_chunk_size_list(num_files_test*max_file_size/min_chunksize);
    printf("max chunk id: %lu\n", num_files_test*max_file_size/min_chunksize);
    //strcpy(fname_ab, dir);
    //fname = fname_ab+strlen(dir);
    
    start_exec = 0;
    for (int i=0; i<num_threads; i++){
      fs_set[i] = {NULL, 0, 0, -1, NULL, NULL, 0};
      pthread_create(&threads[i], NULL, *worker_thread, (void *)&i);
      while (start_exec == 0)
        usleep(1000);
      start_exec = 0;
      //printf("Thread %d created!\n", i);
    }
    for (int i=0; i<num_threads; i++){
      pthread_join(threads[i], NULL);
      //printf("Thread %d joined!\n", i);
    }

    clear_files();
    printf("main Thread exit!\n");
  }else {
    num_files_test = 1;
    //init_chunk_size_list(num_files_test*max_file_size/min_chunksize);
    fs_set[0] = {NULL, 0, 0, -1, NULL, NULL, 0};
    printf("max chunk id: %lu\n", num_files_test*max_file_size/min_chunksize);
    fs_set[0].fname = file_name;
    if(init_fs(&fs_set[0]) == 0){
      run_cdc_with_timer(&fs_set[0]);
      finialize_fs(&fs_set[0]);
    }
  }
  
  collect_all_stats(num_threads);
  if (do_io) {
		uint64_t start = time_nsec(), end;
    close_file(dump_fd);
		end = time_nsec();
    if (fast_skip > 0 && fast_skip != 3)
      dedup_stats.fast_cdtime += end-start;
    else
      dedup_stats.regular_dtime += end-start;
		printf("Close dump fd time :%lu\n", (end-start)/1000);
	}
  
  free(threads);
  free(fs_set);

  sprintf(hname, "hash %s", hash_name);
	if (fast_skip != 100)
		print_stats(hname);

	if (profile){
		print_sequence_list();
		deinit_chunk_sequence_list();
	}


  deinit_chunk_size_dist();
  deinit_fp_pool();
  deinit_chunk_size_list();
  deinit_chunk_boundary_list();

  destroy_per_thread_stats();
  return 0;
}

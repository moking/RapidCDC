#ifndef COMMON_H_H
#define COMMON_H_H

#define _XOPEN_SOURCE 500
#include <stdio.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <bsd/stdlib.h>
#include <string.h>
//#include <immintrin.h>
#include <assert.h>
#include <time.h>
#include <openssl/sha.h>
#include <dirent.h>
#include <pthread.h>


//#include "lib/lz4.h"
#include "./xxhash.h"

#define HASHLEN 256

#define USE_MEMALLOC 1
#define TRACE_MODE 100
#define SEQ_TRACE_MODE 99
#define RAND_OP 4
#define ZERO_LOC_OP 5
#define ZERO_LOC_OP_INS 6
static int op_ins_enable=0;
static int sm_profile = 0;
static int path_switch=0;
static pthread_mutex_t io_lock;

#define JM_MODE 11
#define JB_MODE 12
#define SMART_MODE 10
#define SF_MODE 2
#define FF_MODE 1
#define BASE_MODE 0


static int num_threads=1;
static int list_length=1;
static int lru_enabled = 0;
// 0-list_length-1 hits, list_length: misses
static uint64_t *lru_hits = NULL;

#define BM_SIZE 1024*1024
#define IO_BUF_SIZE 1024*1024*1024
static uint64_t  MAX_FILE_SIZE=(uint64_t)8*1024*1024*1024;

  static	inline uint64_t
time_nsec(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
  return ts.tv_sec * UINT64_C(1000000000) + ts.tv_nsec;
}


#define NUM_TIME 6
struct dedup_stats_st{
	uint64_t total_size;
	uint64_t total_chunks;
	uint64_t uniq_chunks;
	uint64_t uniq_size;
  uint64_t fast_hit_chunks; // fp match + boundary match
  uint64_t fast_miss_chunks; // boundary miss
  uint64_t fast_false_hit_chunks;  //boundary hit + fp miss
  uint64_t num_rollings;     //number of rolling window computation
  uint64_t num_fingerprintings;  // number of fingerprinting
	uint64_t mode_switch; 
	uint64_t num_io; 
	uint64_t num_path_switch;

	uint64_t serial_ns;
  uint64_t regular_ctime;
  uint64_t regular_dtime;
  uint64_t fast_ctime;
  uint64_t fast_cdtime; // chunk+dedup
  uint64_t iotime; // chunk+dedup
};
	
static struct dedup_stats_st dedup_stats={0,0,0,0, 0 ,0, 0,0,0,0, 0, 0, 0, 0, 0, 0, 0};
static struct dedup_stats_st *per_thread_stats = NULL;

static inline void create_per_thread_stats(int num_thread){
  per_thread_stats = (struct dedup_stats_st *)calloc(sizeof(struct dedup_stats_st)*num_thread, 1);
  assert(per_thread_stats);
}

static inline void destroy_per_thread_stats(){
  if(per_thread_stats)
    free(per_thread_stats);
}

static inline void collect_all_stats(int num_thread){
  uint64_t *all = (uint64_t *) &dedup_stats;
  uint64_t *each = NULL;
  int num_item = sizeof(dedup_stats_st)/sizeof(uint64_t);
  
  //printf("num_item %d\n", num_item);
  for (int i=0; i<num_thread; i++){
    each = (uint64_t*)&per_thread_stats[i];
    //printf("each %p %p %lu\n", each, per_thread_stats, (uint8_t*)each-(uint8_t*)per_thread_stats);
    for (int j=0; j<num_item - 6; j++){
      //printf("%d: %p %lu\n", j, each+j, each[j]);
      all[j] += each[j];
    }
    //time
    for (int j= num_item-6; j<num_item; j++){
      //printf("%d: %p %lu\n", j, each+j, each[j]);
      if (all[j] < each[j])
        all[j] = each[j];
    }
  }
}

static int adaptive_window=0;
static uint32_t min_chunksize = 2*1024;
static uint32_t max_chunksize = 64*1024;
static uint32_t break_mask_bit = 14;
static uint32_t break_mask = (1u<<break_mask_bit)-1;
static uint32_t magic_number = 0;
static int fast_skip = 0;
static char *default_hash_str="crc";

static uint8_t *zbuffer = NULL;
static int verbose = 0;
static int blind_jump = 0;
static int jump_with_mark_test = 0;
static int profile=0;
static int sequence_gaps=1024;
static char *output_file = "new-file";
static int do_io=0;
static int do_buf_io=0;
static char *dump_fname = "output.dat";
static char *dump_dir = "/tmp/";
static int dump_fd = 0;

static struct io_buf_st{
	void *buf;
	uint32_t size;
} *io_bufs = NULL;

struct pass_st{
	int op;
	int start;
	int end;
	int iter;
	int size;
	int num_barriers;
} pass;




//[left, right)
struct chunk_boundary{
	uint64_t left;
	uint64_t right;
};

#define vector_idx(table,idx) \
	((__v16si)table)[idx]

#define _A16 __attribute__((__aligned__(16)))
static const uint32_t _A16 crct[256] =
{
	0x00000000,0x77073096,0xEE0E612C,0x990951BA,0x076DC419,0x706AF48F,0xE963A535,0x9E6495A3,
	0x0EDB8832,0x79DCB8A4,0xE0D5E91E,0x97D2D988,0x09B64C2B,0x7EB17CBD,0xE7B82D07,0x90BF1D91,
	0x1DB71064,0x6AB020F2,0xF3B97148,0x84BE41DE,0x1ADAD47D,0x6DDDE4EB,0xF4D4B551,0x83D385C7,
	0x136C9856,0x646BA8C0,0xFD62F97A,0x8A65C9EC,0x14015C4F,0x63066CD9,0xFA0F3D63,0x8D080DF5,
	0x3B6E20C8,0x4C69105E,0xD56041E4,0xA2677172,0x3C03E4D1,0x4B04D447,0xD20D85FD,0xA50AB56B,
	0x35B5A8FA,0x42B2986C,0xDBBBC9D6,0xACBCF940,0x32D86CE3,0x45DF5C75,0xDCD60DCF,0xABD13D59,
	0x26D930AC,0x51DE003A,0xC8D75180,0xBFD06116,0x21B4F4B5,0x56B3C423,0xCFBA9599,0xB8BDA50F,
	0x2802B89E,0x5F058808,0xC60CD9B2,0xB10BE924,0x2F6F7C87,0x58684C11,0xC1611DAB,0xB6662D3D,
	0x76DC4190,0x01DB7106,0x98D220BC,0xEFD5102A,0x71B18589,0x06B6B51F,0x9FBFE4A5,0xE8B8D433,
	0x7807C9A2,0x0F00F934,0x9609A88E,0xE10E9818,0x7F6A0DBB,0x086D3D2D,0x91646C97,0xE6635C01,
	0x6B6B51F4,0x1C6C6162,0x856530D8,0xF262004E,0x6C0695ED,0x1B01A57B,0x8208F4C1,0xF50FC457,
	0x65B0D9C6,0x12B7E950,0x8BBEB8EA,0xFCB9887C,0x62DD1DDF,0x15DA2D49,0x8CD37CF3,0xFBD44C65,
	0x4DB26158,0x3AB551CE,0xA3BC0074,0xD4BB30E2,0x4ADFA541,0x3DD895D7,0xA4D1C46D,0xD3D6F4FB,
	0x4369E96A,0x346ED9FC,0xAD678846,0xDA60B8D0,0x44042D73,0x33031DE5,0xAA0A4C5F,0xDD0D7CC9,
	0x5005713C,0x270241AA,0xBE0B1010,0xC90C2086,0x5768B525,0x206F85B3,0xB966D409,0xCE61E49F,
	0x5EDEF90E,0x29D9C998,0xB0D09822,0xC7D7A8B4,0x59B33D17,0x2EB40D81,0xB7BD5C3B,0xC0BA6CAD,
	0xEDB88320,0x9ABFB3B6,0x03B6E20C,0x74B1D29A,0xEAD54739,0x9DD277AF,0x04DB2615,0x73DC1683,
	0xE3630B12,0x94643B84,0x0D6D6A3E,0x7A6A5AA8,0xE40ECF0B,0x9309FF9D,0x0A00AE27,0x7D079EB1,
	0xF00F9344,0x8708A3D2,0x1E01F268,0x6906C2FE,0xF762575D,0x806567CB,0x196C3671,0x6E6B06E7,
	0xFED41B76,0x89D32BE0,0x10DA7A5A,0x67DD4ACC,0xF9B9DF6F,0x8EBEEFF9,0x17B7BE43,0x60B08ED5,
	0xD6D6A3E8,0xA1D1937E,0x38D8C2C4,0x4FDFF252,0xD1BB67F1,0xA6BC5767,0x3FB506DD,0x48B2364B,
	0xD80D2BDA,0xAF0A1B4C,0x36034AF6,0x41047A60,0xDF60EFC3,0xA867DF55,0x316E8EEF,0x4669BE79,
	0xCB61B38C,0xBC66831A,0x256FD2A0,0x5268E236,0xCC0C7795,0xBB0B4703,0x220216B9,0x5505262F,
	0xC5BA3BBE,0xB2BD0B28,0x2BB45A92,0x5CB36A04,0xC2D7FFA7,0xB5D0CF31,0x2CD99E8B,0x5BDEAE1D,
	0x9B64C2B0,0xEC63F226,0x756AA39C,0x026D930A,0x9C0906A9,0xEB0E363F,0x72076785,0x05005713,
	0x95BF4A82,0xE2B87A14,0x7BB12BAE,0x0CB61B38,0x92D28E9B,0xE5D5BE0D,0x7CDCEFB7,0x0BDBDF21,
	0x86D3D2D4,0xF1D4E242,0x68DDB3F8,0x1FDA836E,0x81BE16CD,0xF6B9265B,0x6FB077E1,0x18B74777,
	0x88085AE6,0xFF0F6A70,0x66063BCA,0x11010B5C,0x8F659EFF,0xF862AE69,0x616BFFD3,0x166CCF45,
	0xA00AE278,0xD70DD2EE,0x4E048354,0x3903B3C2,0xA7672661,0xD06016F7,0x4969474D,0x3E6E77DB,
	0xAED16A4A,0xD9D65ADC,0x40DF0B66,0x37D83BF0,0xA9BCAE53,0xDEBB9EC5,0x47B2CF7F,0x30B5FFE9,
	0xBDBDF21C,0xCABAC28A,0x53B39330,0x24B4A3A6,0xBAD03605,0xCDD70693,0x54DE5729,0x23D967BF,
	0xB3667A2E,0xC4614AB8,0x5D681B02,0x2A6F2B94,0xB40BBE37,0xC30C8EA1,0x5A05DF1B,0x2D02EF8D,
};

static const uint32_t crcu[256] =
{
	0x00000000,0xce3371cb,0x4717e5d7,0x8924941c,0x8e2fcbae,0x401cba65,0xc9382e79,0x070b5fb2,
	0xc72e911d,0x091de0d6,0x803974ca,0x4e0a0501,0x49015ab3,0x87322b78,0x0e16bf64,0xc025ceaf,
	0x552c247b,0x9b1f55b0,0x123bc1ac,0xdc08b067,0xdb03efd5,0x15309e1e,0x9c140a02,0x52277bc9,
	0x9202b566,0x5c31c4ad,0xd51550b1,0x1b26217a,0x1c2d7ec8,0xd21e0f03,0x5b3a9b1f,0x9509ead4,
	0xaa5848f6,0x646b393d,0xed4fad21,0x237cdcea,0x24778358,0xea44f293,0x6360668f,0xad531744,
	0x6d76d9eb,0xa345a820,0x2a613c3c,0xe4524df7,0xe3591245,0x2d6a638e,0xa44ef792,0x6a7d8659,
	0xff746c8d,0x31471d46,0xb863895a,0x7650f891,0x715ba723,0xbf68d6e8,0x364c42f4,0xf87f333f,
	0x385afd90,0xf6698c5b,0x7f4d1847,0xb17e698c,0xb675363e,0x784647f5,0xf162d3e9,0x3f51a222,
	0x8fc197ad,0x41f2e666,0xc8d6727a,0x06e503b1,0x01ee5c03,0xcfdd2dc8,0x46f9b9d4,0x88cac81f,
	0x48ef06b0,0x86dc777b,0x0ff8e367,0xc1cb92ac,0xc6c0cd1e,0x08f3bcd5,0x81d728c9,0x4fe45902,
	0xdaedb3d6,0x14dec21d,0x9dfa5601,0x53c927ca,0x54c27878,0x9af109b3,0x13d59daf,0xdde6ec64,
	0x1dc322cb,0xd3f05300,0x5ad4c71c,0x94e7b6d7,0x93ece965,0x5ddf98ae,0xd4fb0cb2,0x1ac87d79,
	0x2599df5b,0xebaaae90,0x628e3a8c,0xacbd4b47,0xabb614f5,0x6585653e,0xeca1f122,0x229280e9,
	0xe2b74e46,0x2c843f8d,0xa5a0ab91,0x6b93da5a,0x6c9885e8,0xa2abf423,0x2b8f603f,0xe5bc11f4,
	0x70b5fb20,0xbe868aeb,0x37a21ef7,0xf9916f3c,0xfe9a308e,0x30a94145,0xb98dd559,0x77bea492,
	0xb79b6a3d,0x79a81bf6,0xf08c8fea,0x3ebffe21,0x39b4a193,0xf787d058,0x7ea34444,0xb090358f,
	0xc4f2291b,0x0ac158d0,0x83e5cccc,0x4dd6bd07,0x4adde2b5,0x84ee937e,0x0dca0762,0xc3f976a9,
	0x03dcb806,0xcdefc9cd,0x44cb5dd1,0x8af82c1a,0x8df373a8,0x43c00263,0xcae4967f,0x04d7e7b4,
	0x91de0d60,0x5fed7cab,0xd6c9e8b7,0x18fa997c,0x1ff1c6ce,0xd1c2b705,0x58e62319,0x96d552d2,
	0x56f09c7d,0x98c3edb6,0x11e779aa,0xdfd40861,0xd8df57d3,0x16ec2618,0x9fc8b204,0x51fbc3cf,
	0x6eaa61ed,0xa0991026,0x29bd843a,0xe78ef5f1,0xe085aa43,0x2eb6db88,0xa7924f94,0x69a13e5f,
	0xa984f0f0,0x67b7813b,0xee931527,0x20a064ec,0x27ab3b5e,0xe9984a95,0x60bcde89,0xae8faf42,
	0x3b864596,0xf5b5345d,0x7c91a041,0xb2a2d18a,0xb5a98e38,0x7b9afff3,0xf2be6bef,0x3c8d1a24,
	0xfca8d48b,0x329ba540,0xbbbf315c,0x758c4097,0x72871f25,0xbcb46eee,0x3590faf2,0xfba38b39,
	0x4b33beb6,0x8500cf7d,0x0c245b61,0xc2172aaa,0xc51c7518,0x0b2f04d3,0x820b90cf,0x4c38e104,
	0x8c1d2fab,0x422e5e60,0xcb0aca7c,0x0539bbb7,0x0232e405,0xcc0195ce,0x452501d2,0x8b167019,
	0x1e1f9acd,0xd02ceb06,0x59087f1a,0x973b0ed1,0x90305163,0x5e0320a8,0xd727b4b4,0x1914c57f,
	0xd9310bd0,0x17027a1b,0x9e26ee07,0x50159fcc,0x571ec07e,0x992db1b5,0x100925a9,0xde3a5462,
	0xe16bf640,0x2f58878b,0xa67c1397,0x684f625c,0x6f443dee,0xa1774c25,0x2853d839,0xe660a9f2,
	0x2645675d,0xe8761696,0x6152828a,0xaf61f341,0xa86aacf3,0x6659dd38,0xef7d4924,0x214e38ef,
	0xb447d23b,0x7a74a3f0,0xf35037ec,0x3d634627,0x3a681995,0xf45b685e,0x7d7ffc42,0xb34c8d89,
	0x73694326,0xbd5a32ed,0x347ea6f1,0xfa4dd73a,0xfd468888,0x3375f943,0xba516d5f,0x74621c94,
};


struct file_struct{
	char *fname;
	uint64_t length, test_length;
	int fd;
	void *map;
	uint8_t *breakpoint_bm;
	uint8_t *breakpoint_bm_base; // for serial chunking method as the base
	uint64_t next_start;  // next chunk start, used by next_chunk()
};


static void *map_file(struct file_struct *fs){
  int ret;
	fs->fd = open(fs->fname, O_RDONLY);
	if (fs->fd < 0) return NULL;
	fs->length = lseek(fs->fd, 0, SEEK_END);
	if (fs->test_length == 0 || fs->test_length > fs->length)
		fs->test_length = fs->length;
	fs->map = (void *)calloc(fs->test_length+10, sizeof(char));
  assert(fs->map);
  assert( 0 == lseek(fs->fd, 0, SEEK_SET)); 
  ret = read(fs->fd, fs->map, fs->test_length);
  if (ret != fs->test_length){
    printf("fd %d ret %d %lu\n", fs->fd, ret, fs->test_length);
    assert(0);
  }

	return fs->map;
}

static void unmap_file(struct file_struct *fs){
	if(fs->map > 0){
		free(fs->map);
	}
	if (fs->fd > 0)
		close(fs->fd);
}

static struct file_struct *fs_set;
static char *file_name = NULL;
static int file_test_length = 0;

static char *dir = NULL;
typedef int (*phase_one_func)(struct file_struct *fs);
static phase_one_func chunk_f = NULL;
static int num_files_test = 0;
static char *hash_name = NULL;
static char *bench_name = "default";

static int fs_idx(struct file_struct *fs){
  return ((uint8_t *)fs-(uint8_t*)fs_set)/sizeof(struct file_struct);
}


int chunking_phase_one_serial_gear(struct file_struct *fs);
//int chunking_phase_one_parallel_gear(struct file_struct *fs);
int chunking_phase_one_serial_crc(struct file_struct *fs);

static int set_chunk_func(char *name){
	if (strcmp(name, "gear") == 0){
		chunk_f = chunking_phase_one_serial_gear;
	} else if (strcmp(name, "gear:p") == 0)
    assert(0);
	else if (strcmp(name, "crc") == 0){
		chunk_f = chunking_phase_one_serial_crc;
	} else if (strcmp(name, "crc:p0") == 0)
    assert(0);
	else if (strcmp(name, "crc:p1") == 0)
    assert(0);
	else{
		printf("Only Valid hash function as below accepted:\n");
		printf(" gear ; ");
		printf("crc ; ");
		return 1;
	}
	return 0;
}


static inline void help(){
	printf("\nHelp: -f fname -m min -M max_chunksize_KB -ts test_size -nm magic_number -d dir -bmb num -H crc/gear -LS list-length -th threads\n");
	printf("NOTE: either -f or -d must be used. If -f and -d is used together, -d will be used, the dir (end with '/') should include all files, subdir is not accepted\n");
	printf("Available RapidCDC modes include:\n");
	printf("-FF: FF+RWT+FPT (Fingerprint Test)\n");
	printf("-SF: FF+RWT (Rolling Window Test)\n");
	printf("-JB: FF without further boundary test\n");
	printf("-JM: FF+MT (Marker Test)\n");
	printf("For more configuration options, refer to parse_args()\n\n");
}

int parse_args(int argc, char *argv[]){
	for (int i=1; i<argc; i++){
		if(strncmp(argv[i], "-f", 2) == 0){
			assert(i<argc-1);
		  file_name = argv[i+1];
			i++;
		}else if(strncmp(argv[i], "-m", 2) == 0){
			assert(i<argc-1);
			min_chunksize = atoi(argv[i+1])*1024;
			i++;
		}else if(strncmp(argv[i], "-M", 2) == 0){
			assert(i<argc-1);
			max_chunksize = atoi(argv[i+1])*1024;
			i++;
		}else if(strncmp(argv[i], "-ts", 3) == 0){
			assert(i<argc-1);
			file_test_length = atoi(argv[i+1])*1024*1024;
			i++;
		}else if(strncmp(argv[i], "-nm", 3) == 0){
			assert(i<argc-1);
			magic_number = atoi(argv[i+1]);
			i++;
		}else if(strncmp(argv[i], "-N", 2) == 0){
			assert(i<argc-1);
			num_files_test = atoi(argv[i+1]);
			i++;
		}else if(strncmp(argv[i], "-bmb", 4) == 0){
			assert(i<argc-1);
			break_mask_bit = atoi(argv[i+1]);
			break_mask = (1u<<break_mask_bit)-1;
			i++;
		}else if(strncmp(argv[i], "-d", 2) == 0){
			assert(i<argc-1);
			dir = argv[i+1];
			i++;
		}else if(strncmp(argv[i], "-th", 3) == 0){
			assert(i<argc-1);
			num_threads = atoi(argv[i+1]);
			i++;
		}else if(strncmp(argv[i], "-LS", 3) == 0){
			assert(i<argc-1);
			list_length = atoi(argv[i+1]);
			i++;
		}else if(strncmp(argv[i], "-H", 2) == 0){
			assert(i<argc-1);
			hash_name = argv[i+1];
			i++;
		}else if(strncmp(argv[i], "-B", 2) == 0){
			assert(i<argc-1);
			bench_name = argv[i+1];
			i++;
		}else if (strncmp(argv[i], "-LRU", 4) == 0){
			lru_enabled = 1;  //fast 
		}else if (strncmp(argv[i], "-FF", 3) == 0){
			fast_skip = 1;  //fast 
		}else if (strncmp(argv[i], "-SF", 3) == 0){
			fast_skip = 2;  //super fast
		}else if (strncmp(argv[i], "-FSC", 4) == 0){
			fast_skip = 3;  //fixed-size-chunking
		}else if (strncmp(argv[i], "-SQ", 3) == 0){
			fast_skip = SEQ_TRACE_MODE;  //fixed-size-chunking
			sm_profile = 1;
		}else if (strncmp(argv[i], "-T", 2) == 0){
			fast_skip = TRACE_MODE;  //generate trace
			pass.op = atoi(argv[i+1]);
			pass.start = atoi(argv[i+2]);
			pass.end = atoi(argv[i+3]);
			pass.iter = atoi(argv[i+4]);
			pass.size = atoi(argv[i+5]);
			if (pass.op == ZERO_LOC_OP_INS){
				pass.op = ZERO_LOC_OP;
				op_ins_enable = 1;
			}
			if (pass.end > 100){
				pass.num_barriers = pass.end - 100;
				if (pass.num_barriers > pass.iter)
					pass.num_barriers = pass.iter;
				pass.end = 100;
			}else{
					pass.num_barriers = pass.iter;
			}
			i+=5;
		}else if (strncmp(argv[i], "-AW", 3) == 0){
			adaptive_window = 1;
		}else if (strncmp(argv[i], "-PS", 3) == 0){
			path_switch = 1;
		}else if (strncmp(argv[i], "-v", 2) == 0){
			verbose = 1;
		}else if (strncmp(argv[i], "-JB", 3) == 0){
			blind_jump = 1;
			fast_skip = 2;
		}else if (strncmp(argv[i], "-JM", 3) == 0){
			jump_with_mark_test = 1;
			fast_skip = 2;
		}else if (strncmp(argv[i], "-P", 2) == 0){
			profile = 1;
		}else if(strncmp(argv[i], "-G", 2) == 0){
			assert(i<argc-1);
			sequence_gaps = atoi(argv[i+1]);
			i++;
		}else if(strncmp(argv[i], "-o", 2) == 0){
			assert(i<argc-1);
			output_file= argv[i+1];
			i++;
		}else if(strncmp(argv[i], "-w", 2) == 0){
			assert(i<argc-1);
      do_io = 1;
			dump_dir= argv[i+1];
			i++;
		}else if(strncmp(argv[i], "-b", 2) == 0){
			assert(i<argc-1);
      do_io = 1;
			do_buf_io = 1;
			dump_dir= argv[i+1];
			i++;
		}else{
			help();
			return 1;
		}
	}

	if (hash_name == NULL){
    hash_name=default_hash_str;
	} 

	if (set_chunk_func(hash_name))
		return 1;

	if (jump_with_mark_test){
		fast_skip = 2;
		blind_jump = 0;
	}else{
		if (blind_jump)
			fast_skip = 2;
	}

	//printf("INFO: hash %s\n", hash_name);
	if (file_name == NULL && dir == NULL){
		help();
		return 1;
	}
	else
		return 0;
}


static inline int reach_file_end(struct file_struct *fs, uint64_t offset){
  return (fs->test_length == offset);
}



static inline int reach_end(struct file_struct *fs){
	return fs->length <= fs->next_start;
}

static inline uint64_t bytes_left(struct file_struct *fs){
	return fs->length - fs->next_start;
}

static inline int is_breakpoint(struct file_struct *fs, uint64_t idx){
	uint8_t b = fs->breakpoint_bm[idx/8];
	return ((b>>(idx%8)) & 0x1);
}


static inline int compute_fingerprint(struct file_struct *fs, struct chunk_boundary *cb, uint8_t *hash){
  SHA1((uint8_t*)fs->map+cb->left, cb->right-cb->left, hash);
  dedup_stats.num_fingerprintings++;
  return 0;
}

static inline void print_fingperint(uint8_t *hash, int len){
	uint64_t v = XXH64(hash,len,0);
	printf("%016lx", v);
#if 0
	for(int i=0; i<len; i++){
		printf("%x", hash[i]);
	}
#endif
	printf(" ");
}

//return 1 if match; else return 0
static inline int compare_fingerprint(uint8_t *hash1, uint8_t *hash2, int len){
	if (len %8 == 0){
			for(int i=0; i< len; i+=8){
				if (*(uint64_t*)(hash1+i) !=  *(uint64_t*)(hash2+i))
					return 0;
			}
			return 1;
	} else{
			for(int i=0; i< len; i+=4){
				if (*(uint32_t*)(hash1+i) !=  *(uint32_t*)(hash2+i))
					return 0;
			}
			return 1;
	}
}


struct fp_entry_st{
	uint8_t hash[SHA_DIGEST_LENGTH];
  int chunk_id;
  int shared; // 1 if multiple lbn share the same fp
	struct fp_entry_st *next;
  int next_sizes[];
};

static void record_next_size(struct fp_entry_st *fp, int next_size, int pos=0){
  int i;

  if(next_size&0xffffff <= 0){
    printf("%lu next size %x\n", *(uint64_t*)fp->hash, next_size);
    exit(1);
  }
  next_size -= (min_chunksize-1);
  if (lru_enabled == 0){
    if (fp->next_sizes[0] == 0)
      fp->next_sizes[0] = next_size;
    return;
  }else{
    if (list_length == 1 || fp->next_sizes[0] == 0){
      fp->next_sizes[0] = next_size;
      return;
    }
  }

  if (pos > 0){
    fp->next_sizes[pos] = next_size;
  }
  //if (next_size != fp->next_sizes[0] ){
    //printf("%lu next size %d old size %d\n", *(uint64_t*)fp->hash, next_size, fp->next_sizes[0]);
  //}
  for (i = 0; i<list_length; i++){
    if (fp->next_sizes[i] == 0){
      memmove(fp->next_sizes+1, fp->next_sizes,i*sizeof(int)); 
      fp->next_sizes[0] = next_size;
      return;
    }
    if (fp->next_sizes[i] == next_size){
      break;
    }
  }
  if ( i < list_length){
    if(i > 0){
      memmove(fp->next_sizes+1, fp->next_sizes,i*sizeof(int)); 
      fp->next_sizes[0] = next_size;
    }
  }else{
      memmove(fp->next_sizes+1, fp->next_sizes,(list_length-1)*sizeof(int)); 
      fp->next_sizes[0] = next_size;
  }
}

static int next_chunk_size(struct fp_entry_st *fp, int idx){
  int next_size;
  if (idx >= list_length || fp->next_sizes[idx] == 0)
    return 0;
  next_size = fp->next_sizes[idx] + min_chunksize-1;
  //if (idx > 0)
    //printf("Fetch %lu next size %d idx %d\n", *(uint64_t*)fp->hash, next_size, idx);
  return next_size;
}


struct fp_pool{
	int num_slots;
	int fp_len;
  pthread_mutex_t *slot_locks;
	struct fp_entry_st* slots[];
};
static struct fp_pool *hash_pool = NULL;

static int *size_list = NULL;
static uint8_t *recipe_hash = NULL;
static uint32_t *marker_list=NULL;
//static int chunk_id = 0;

static void init_chunk_size_list(uint64_t chunk_num){
  size_list = (int *) calloc(sizeof(int)*chunk_num, 1);
	if (path_switch){
		recipe_hash = (uint8_t *)calloc(sizeof(uint8_t)*chunk_num, SHA_DIGEST_LENGTH);
		assert(recipe_hash);
	}
  assert(size_list);
}

static void deinit_chunk_size_list(){
  if (size_list)
    free(size_list);
	if (recipe_hash)
		free(recipe_hash);
  size_list = NULL;
	recipe_hash = NULL;
}

static inline void insert_size_list(uint64_t idx, int size, uint32_t mark, uint8_t *fp = NULL){
	size_list[idx] = (mark << 24) + size;
	if (path_switch){
		assert(fp);
		memcpy(&recipe_hash[idx*SHA_DIGEST_LENGTH], fp, SHA_DIGEST_LENGTH);
	}
}

static inline uint8_t *recipe_fp(uint64_t cid){
	return &recipe_hash[cid*SHA_DIGEST_LENGTH];
}

//old_fp has been used for jumping, but failed
static inline void update_path(uint64_t cur_cid, fp_entry_st *old_fp){
	uint8_t *fp = NULL;
	int size, new_size;
	if (old_fp == NULL)
		return;
	fp = recipe_fp(cur_cid-1); 
	if (compare_fingerprint(fp, old_fp->hash, hash_pool->fp_len)){
		old_fp->chunk_id = cur_cid-1;
		dedup_stats.num_path_switch ++;
	}
}

//str points to the end of the chunk
static inline int mark_match(uint64_t idx, uint8_t *str){
	//return marker_list[idx] == *(uint32_t*)(str-sizeof(uint32_t));
	return marker_list[idx] == *(str-1);
}

//static inline uint32_t extract_mark(uint8_t *str){
static inline uint8_t extract_mark(uint8_t *str){
	return *(str-1);
}

static struct sequence_list_st {
	int *chunk_sequence_len_list;
	int size;
  int long_chunk_cnt; // for too long chunk, we record its len in terms of chunk here
} sequence_list;

static void init_chunk_sequence_list(int chunk_num){
	sequence_list.size = chunk_num;
  sequence_list.chunk_sequence_len_list = (int *) calloc(sizeof(int)*chunk_num, 1);
  assert(sequence_list.chunk_sequence_len_list);
  sequence_list.long_chunk_cnt = 0;
}
static void deinit_chunk_sequence_list(){
  if (sequence_list.chunk_sequence_len_list)
    free(sequence_list.chunk_sequence_len_list);
	sequence_list.chunk_sequence_len_list = NULL;
}

static int update_chunk_sequence_list(int idx){
	if (idx >= sequence_list.size-1){
    sequence_list.long_chunk_cnt += idx;
		idx = sequence_list.size-1;
  }
	sequence_list.chunk_sequence_len_list[idx] ++;
	return sequence_list.chunk_sequence_len_list[idx];
}

static void print_sequence_list(void){
	printf("START: PRINT SEQUENCE LIST FOR %s avg %d mini %d max %d num_files %d\n", bench_name, 1<<break_mask_bit, min_chunksize, max_chunksize, num_files_test);
	for (int i=0; i< sequence_list.size; i++)
		if (sequence_list.chunk_sequence_len_list[i] > 0)
			printf("idx %d times %d cnt %d\n", i, sequence_list.chunk_sequence_len_list[i]
          , i== sequence_list.size-1? sequence_list.long_chunk_cnt: sequence_list.chunk_sequence_len_list[i]*i);
	printf("END: PRINT SEQUENCE LIST FOR %s avg %d mini %d max %d\n", bench_name, 1<<break_mask_bit, min_chunksize, max_chunksize);
}


struct chunk_size_dist{
  int start_size;
  int end_size;
  int stride;
  int *data;
};


static struct chunk_size_dist chunk_dist;

static void init_chunk_size_dist(int mini, int maxi, int stride){
  int num = (maxi-mini)/stride;
  assert(mini<maxi);
  chunk_dist.start_size = mini;
  chunk_dist.end_size = maxi;
  chunk_dist.stride = stride;
  chunk_dist.data = NULL;
  chunk_dist.data =(int*) calloc(num+1, sizeof(int));
  assert(chunk_dist.data);

  zbuffer = (uint8_t*) calloc(sizeof(uint8_t)*max_chunksize, 1);
  assert(zbuffer);
}
static void deinit_chunk_size_dist(){
  if (chunk_dist.data)
    free(chunk_dist.data);
  chunk_dist.data = NULL;

  if( zbuffer)
	  free(zbuffer);
  zbuffer = NULL;
}

static inline void update_chunk_dist(int size){
  int idx = 0;
  if (size > chunk_dist.end_size)
	  size = chunk_dist.end_size;
  if (size < chunk_dist.start_size)
	  size = chunk_dist.start_size;
  idx = (size-chunk_dist.start_size)/chunk_dist.stride;
  assert(size <= chunk_dist.end_size && idx >= 0);
  chunk_dist.data[idx] ++;
}

static void print_chunk_dist(){
  int num = (chunk_dist.end_size-chunk_dist.start_size)/chunk_dist.stride;
  assert(chunk_dist.data);
  for (int i = 0; i< num; i++){
    printf("[%d-%d): %d\n", chunk_dist.start_size+i*chunk_dist.stride, chunk_dist.start_size+(i+1)*chunk_dist.stride, chunk_dist.data[i]);
  }
}


static int MAX_CHUNK_IN_FILE=1*1024*1024;
static chunk_boundary *chunk_boundary_list = NULL;
static int *next_chunk_idx = NULL;

static void init_chunk_boundary_list(){
  chunk_boundary_list = (struct chunk_boundary *) calloc(num_threads, sizeof(struct chunk_boundary)*MAX_CHUNK_IN_FILE);
  next_chunk_idx = (int*) calloc(sizeof(int), num_threads);
  assert(chunk_boundary_list);
  assert(next_chunk_idx);
}

static inline chunk_boundary *chunk_boundarys(int tid){
  return chunk_boundary_list+MAX_CHUNK_IN_FILE*tid;
}


static void reset_chunk_idx_in_file(int tid){
  next_chunk_idx[tid] = 0;
}
static void reset_chunk_boundary_list(int tid){
  reset_chunk_idx_in_file(tid);
  if(chunk_boundary_list == NULL)
    init_chunk_boundary_list();
  else
    bzero(chunk_boundarys(tid), sizeof(chunk_boundary)*MAX_CHUNK_IN_FILE);
}

static void deinit_chunk_boundary_list(){
  if(chunk_boundary_list)
    free(chunk_boundary_list);
  if(next_chunk_idx)
    free(next_chunk_idx);
  next_chunk_idx = NULL;
  chunk_boundary_list = NULL;
}

static void insert_chunk_boundary(int tid, struct chunk_boundary *cb){
  assert(next_chunk_idx[tid] < MAX_CHUNK_IN_FILE && chunk_boundary_list);
  //if ( next_chunk_idx > 0 && cb->left < chunk_boundary_list[next_chunk_idx-1].right)
  assert(cb->left < cb->right);
  (chunk_boundarys(tid))[next_chunk_idx[tid]].left = cb->left;
  (chunk_boundarys(tid))[next_chunk_idx[tid]].right = cb->right;

  //assert(cb->right > cb->left);
  //update_chunk_dist(cb->right-cb->left);
	//if (verbose)
		//printf("%d: %lu:%lu size %lu\n", next_chunk_idx, cb->left, cb->right, cb->right-cb->left);
  next_chunk_idx[tid]++;
} 

static struct chunk_boundary * next_chunk_boundary(int tid, struct chunk_boundary *cb){
  assert(next_chunk_idx[tid] < MAX_CHUNK_IN_FILE && chunk_boundary_list);
  cb->left = (chunk_boundarys(tid))[next_chunk_idx[tid]].left;
  cb->right = (chunk_boundarys(tid))[next_chunk_idx[tid]].right;
  if (cb->left == cb->right)
    return NULL;
  next_chunk_idx[tid]++;
  return cb;
} 






static void init_fp_pool(int slot_cnt, int fp_len){
	hash_pool = (struct fp_pool*)calloc(sizeof(struct fp_pool)+slot_cnt*sizeof(void*), 1);
	assert(hash_pool);
	hash_pool->num_slots = slot_cnt;
	hash_pool->fp_len = fp_len;
  hash_pool->slot_locks = (pthread_mutex_t *)calloc(sizeof(pthread_mutex_t)*slot_cnt, 1);
  assert(hash_pool->slot_locks);
  if (lru_enabled){
    lru_hits = (uint64_t *)calloc(sizeof(uint64_t), list_length+1);
    assert(lru_hits);
  }
}

static inline struct fp_entry_st *new_fp_entry(uint8_t *hash, int len){
	struct fp_entry_st *p = (struct fp_entry_st*) calloc(1, sizeof(struct fp_entry_st) + list_length*sizeof(int));  //next_sizes
	assert(p);
	memcpy(p->hash, hash, len);
  //p->chunk_id = chunk_id;
	return p;
}

static inline void free_fp_entry(struct fp_entry_st *entry){
	if(entry)
		free(entry);
}

static void deinit_fp_pool(){
	if(hash_pool){
		struct fp_entry_st *item;
		for(int i=0; i<hash_pool->num_slots; i++){
			item = hash_pool->slots[i];
			while(item){
				hash_pool->slots[i] = item->next;
				free_fp_entry(item);
				item = hash_pool->slots[i];
			}
		}
    free(hash_pool->slot_locks);
    free(hash_pool);
	}
  if (lru_hits)
    free(lru_hits);
}

static inline uint32_t table_index(uint8_t *hash){
	uint32_t idx = *(uint32_t*)hash;
	if(hash_pool == NULL)
		return -1;
	return idx%hash_pool->num_slots;
}

//static fp_entry_st *last_fp_item = NULL;
static uint64_t unique_fp = 0;

//static inline void lock_hash_slot(uint32_t idx){
static inline void lock_hash_slot(uint8_t *hash){
	uint32_t idx = table_index(hash);
  assert(idx < hash_pool->num_slots);
  pthread_mutex_lock(&hash_pool->slot_locks[idx]);
}

//static inline void unlock_hash_slot(uint32_t idx){
static inline void unlock_hash_slot(uint8_t *hash){
	uint32_t idx = table_index(hash);
  assert(idx < hash_pool->num_slots);
  pthread_mutex_unlock(&hash_pool->slot_locks[idx]);
}


static struct fp_entry_st* insert_fp(uint8_t *hash, uint64_t next_size = 0){
	uint32_t idx = table_index(hash);
	struct fp_entry_st *item = new_fp_entry(hash, hash_pool->fp_len);
	item->next = hash_pool->slots[idx];
	//item->chunk_id = chunkid;
  //item->next_sizes[0] = next_size;
  //lock_hash_slot(idx);
	hash_pool->slots[idx] = item;
  //unlock_hash_slot(idx);

  unique_fp++;
  //printf("item at %x inserted at %d slot\n", *(int*)hash, idx);

	return item;
}

static fp_entry_st* lookup_fp(uint8_t *hash){
	uint32_t idx = table_index(hash);
  //lock_hash_slot(idx);
	struct fp_entry_st *item = hash_pool->slots[idx];
	while(item){
		if(compare_fingerprint(hash, item->hash, hash_pool->fp_len)){
      if(item->shared == 0){
        item->shared = 1;
        unique_fp--;
      }
      //unlock_hash_slot(idx);
			return item;
    }
		item = item->next;
	}
  //unlock_hash_slot(idx);
	return NULL;
}


static void print_lru_hits(){
  if (lru_enabled){
    assert(lru_hits);
    printf("LRU_HIT %d locations\n", list_length);
    for (int i=0;i<list_length; i++){
      printf("Hit at ls[%d] %lu\n", i, lru_hits[i]);
    }
    printf("LRU misses %lu\n", lru_hits[list_length]);
  }
}


static void print_stats(char *opt){
	int mode = fast_skip;

  //collect_all_stats(num_threads);
  //return;
  
	if (strlen(opt) > 0) {
		printf("Output: mini_chunksize %u max_chunksize %u expect_avg_chunksize %u magic_number %d %s bench %s", min_chunksize, max_chunksize, 1<<break_mask_bit, magic_number, opt, bench_name);
	}else{
		printf("Output: mini_chunksize %u max_chunksize %u expect_avg_chunksize %u magic_number %d bench %s", min_chunksize, max_chunksize, 1<<break_mask_bit, magic_number, bench_name);
	}
  if (jump_with_mark_test)
    mode = JM_MODE;
  else if (blind_jump)
			mode = JB_MODE;
  printf(" lru_enabled %d list_length %d", lru_enabled, list_length);
  printf(" path_switch %d mode_switch %lu unique_bytes %lu total_bytes %lu unique_chunks %lu total_chunks %lu dedup_ratio %.2f avg_chunk_size %.2f run_mode %d fast_hit_boundary %lu fast_miss_chunks %lu fast_false_hit_chunks %lu unique_FP %lu num_rollings %lu num_fingerprintings %lu num_io %lu num_path_switch %lu", path_switch, dedup_stats.mode_switch, dedup_stats.uniq_size, dedup_stats.total_size, dedup_stats.uniq_chunks, dedup_stats.total_chunks, 1.0*dedup_stats.total_size/dedup_stats.uniq_size, dedup_stats.total_size/dedup_stats.total_chunks*1.0, mode, dedup_stats.fast_hit_chunks, dedup_stats.fast_miss_chunks, dedup_stats.fast_false_hit_chunks, unique_fp, dedup_stats.num_rollings, dedup_stats.num_fingerprintings, dedup_stats.num_io, dedup_stats.num_path_switch);

    printf(" regular_ctime %lu us regular_dtime %lu us fast_ctime %lu us fast_time %lu us iotime %lu us num_threads %d END\n"
        , dedup_stats.regular_ctime /1000, dedup_stats.regular_dtime/1000, dedup_stats.fast_ctime/1000
        , dedup_stats.fast_cdtime/1000, dedup_stats.iotime/1000, num_threads);
    //print_chunk_dist();
    print_lru_hits();
}

static int init_fs(struct file_struct *fs){
	if (map_file(fs) == NULL){
		printf("Error: map file %s failed\n", fs->fname);
		return 1;
	}

	return 0;
}


static void finialize_fs(struct file_struct *fs)
{
	unmap_file(fs);
	fs->test_length = fs->length = fs->next_start = 0;
}


static dirent **namelist = NULL;
static int num_files;
pthread_mutex_t file_lock;

static int filter(const struct dirent *de)
{
	if (de->d_type == DT_REG && strcmp(de->d_name, ".") != 0)
		return 1;
	return 0;
}

static int collect_files(char *dir){
	num_files = scandir(dir, &namelist, filter, alphasort);
	if (num_files < 0){
		perror("scandir");
		return 0;
	} else {
		if (num_files_test == 0)
			num_files_test = num_files;
		printf("Info: tatal %d files in %s, %d files to be tested\n", num_files, dir, num_files_test);
		return num_files;
	}
}
static char *next_file(char *filename){
  //add lock here
  pthread_mutex_lock(&file_lock);
	if (num_files <=0  || num_files_test <= 0){
    pthread_mutex_unlock(&file_lock);
    return NULL;
  }

	strcpy(filename, namelist[--num_files]->d_name);
  free(namelist[num_files]);
	//printf("Processing %s\n",filename);
  num_files_test--;
  pthread_mutex_unlock(&file_lock);
	return filename;
}

static void clear_files(){
  for (int i=0; i< num_files; i++)
    free(namelist[i]);
	free(namelist);
}


static void print_pass(){
	printf("pass: op %d %d-%d iter %d size %d\n", pass.op, pass.start, pass.end, pass.iter, pass.size);
}

struct op_st{
	int op; // 1: insert, 2: update, 3: delete, 4: append
	int chunk_id;
	int offset;
	int size; 
} *ops = NULL;
int num_ops = 0;

static int init_op_struct(struct pass_st *passes){
	if (passes->op == ZERO_LOC_OP){
		ops = (struct op_st *)calloc(sizeof(struct op_st)*dedup_stats.total_chunks+1, 1);
		num_ops = dedup_stats.total_chunks+1;
	} else{
		ops = (struct op_st *)calloc(sizeof(struct op_st)*passes->iter, 1);
		num_ops = passes->iter;
	}
	return num_ops;
}

static void deinit_op_struct(void){
	if (ops )
		free (ops);
	ops = NULL;
}

static void print_op_struct(void){
	for (int i=0; i<num_ops; i++)
		printf("%d: op %d chunk %d offset %d size %d\n", i, ops[i].op, ops[i].chunk_id, ops[i].offset, ops[i].size);
}

static void swap_two_ops(int i, int j){
	struct op_st tmp = ops[i];
	ops[i] = ops[j];
	ops[j] = tmp;
}

// if two ops in the same chunk, just use the first one and ignore the others
static void sort_op_struct(void){
	int offset, op, size;
	for (int i=0; i<num_ops; i++){
		for (int j = i+1; j < num_ops; j++){
			if (ops[i].chunk_id > ops[j].chunk_id)
				swap_two_ops(i,j);
		}
	}
}

static int extract_ops(struct pass_st *passes, int num){
	int start, end, iter, offset, len, cid;
	int op;
	int idx = 0;
	struct chunk_boundary *cb;

	for (int i=0; i<num; i++){
		start = passes[i].start;
		end = passes[i].end;
		iter = passes[i].iter;
		op = passes[i].op;

		for (int j=0; j<iter; j++){
			if (end == start)
				cid = dedup_stats.total_chunks*end/100;
			else{
				cid = dedup_stats.total_chunks*start/100+time_nsec()%(dedup_stats.total_chunks*(end-start)/100);
			}

			cb = &chunk_boundary_list[cid];
			offset = time_nsec()%(cb->right-cb->left);

			if (passes[i].size < 5)
				len = passes[i].size;
			else
				len = time_nsec()%passes[i].size;
			while (len == 0)
				len = time_nsec()%passes[i].size;

			if (offset + len > cb->right-cb->left)
				offset = cb->right-cb->left-len;

			if ( op == RAND_OP)
				ops[idx].op = time_nsec()%(RAND_OP-1)+1;
			else
				ops[idx].op = op;
			ops[idx].offset = offset;
			ops[idx].size = len;
			ops[idx].chunk_id = cid;
			idx ++;
		}
	}
	sort_op_struct();
	//print_op_struct();
	return idx;
}

static int extract_static_ops(int tid, struct pass_st *passes, int num){
	int start, end, iter, offset, len, cid, num_bar = 0, next_start=0;
	int op;
	int idx = 0, j=0;
	struct chunk_boundary *cb;
	int seq_len = 0;
	uint64_t range = 0;

	for (int i=0; i<num; i++){
		start = passes[i].start;
		end = passes[i].end;
		iter = passes[i].iter;
		op = passes[i].op;
		len = passes[i].size;
		num_bar = passes[i].num_barriers;

		if ( op == ZERO_LOC_OP){
			int j = time_nsec()%2;
			for (; j< per_thread_stats[tid].total_chunks; j+=2){
				cid=j;
				cb = &chunk_boundary_list[cid];
				if (op_ins_enable){
					ops[idx].op = 1;
					ops[idx].offset = (cb->right-cb->left)/2;
				} else{
					ops[idx].op = 2;
					ops[idx].offset = 0;
				}
				ops[idx].size = len;
				ops[idx].chunk_id = cid;
				idx ++;
			}
			printf("cid: %d idx %d\n", j, idx);
			return idx;
		}

		range = per_thread_stats[tid].total_chunks*end/100 - (iter-num_bar);
		next_start = per_thread_stats[tid].total_chunks*start/100;
		seq_len = range/num_bar;
		for (j=0; j<num_bar; j++){
			if (end == start)
				cid = per_thread_stats[tid].total_chunks*end/100;
			else{
				cid = next_start + j*seq_len;
			}
      if (cid >= per_thread_stats[tid].total_chunks)
        cid = per_thread_stats[tid].total_chunks-1;

      offset = 0;
      len = passes[i].size;
			if (offset + len > cb->right-cb->left)
				offset = cb->right-cb->left-len;

			if ( op == RAND_OP)
				ops[idx].op = time_nsec()%(RAND_OP-1)+1;
			else{
					ops[idx].op = op;
			}

			ops[idx].offset = offset;
			ops[idx].size = len;
			ops[idx].chunk_id = cid;
			idx ++;
		}
		for (j=0; j< iter-num_bar; j++){
			cid=range+j;
      offset = 0;
      len = passes[i].size;
			if ( op == RAND_OP)
				ops[idx].op = time_nsec()%(RAND_OP-1)+1;
			else{
					ops[idx].op = op;
			}
			ops[idx].offset = offset;
			ops[idx].size = len;
			ops[idx].chunk_id = cid;
			idx ++;
		}

		printf("Total chunk %lu, range %d, Sequence Len: %d num_bar %d\n", per_thread_stats[tid].total_chunks, range, seq_len, num_bar);
	}
	//sort_op_struct();
  //print_op_struct();
	return idx;
}




static struct op_st *next_op(){
	static int idx = 0;
	if (idx >= num_ops || ops[idx].size == 0)
		return NULL;
	return &ops[idx++];
}

static char *random_buf = NULL;
static uint64_t random_size = 0, random_offset=0;
static char *random_data(int len){
	if (random_buf == NULL){
		random_buf = (char *) calloc(len, 1);
		assert(random_buf);
		arc4random_buf(random_buf, len);
		random_size = len;
		return random_buf;
	}else{
		uint64_t idx; 
		if (random_size-random_offset < len){
			idx = random_size-len;
			random_offset = 0;
		}else{
			idx=random_offset;
			random_offset += len;
		}
		return &random_buf[idx];
	}
}

static int create_file(char *dir, char *fname){
	int fd = 0;
	char path[256];
	bzero(path, sizeof(path));
	if (dir == NULL)
		strcpy(path, "/tmp/");
	else
		strcpy(path, dir);
	strcat(path, "/");
	strcat(path, fname);
	printf("Creating a file: %s\n", path);
	fd = open(path, O_LARGEFILE|O_NOATIME|O_CREAT|O_RDWR|O_TRUNC, 0644);
	assert(fd > 0);
	return fd;
}

static int create_dump_file(char *dir, char *fname){
	int fd = 0;
	char path[256];
	bzero(path, sizeof(path));
	if (dir == NULL)
		strcpy(path, "/tmp/");
	else
		strcpy(path, dir);
	strcat(path, "/");
	strcat(path, fname);
	printf("Creating a file: %s\n", path);
	fd = open(path, O_LARGEFILE|O_NOATIME|O_CREAT|O_RDWR, 0644);
	assert(fd > 0);
  if (lseek64(fd, 0, SEEK_END) < MAX_FILE_SIZE){
    lseek64(fd, MAX_FILE_SIZE-4, SEEK_SET);
    write(fd, path, 4);
  }

	if (do_buf_io){
    io_bufs = (struct io_buf_st *)calloc(sizeof(struct io_buf_st), num_threads);
    assert(io_bufs);
    for (int i=0; i<num_threads; i++){
      io_bufs[i].buf = calloc(IO_BUF_SIZE, num_threads);
      assert(io_bufs[i].buf);
      io_bufs[i].size = 0;
    }
	}
   
	return fd;
}

static void *per_thread_iobuf(int tid){
  assert(do_buf_io && io_bufs && tid < num_threads);
  return io_bufs[tid].buf;
}



static int dump_file(int fd, char *str, int len){
	assert(str && len);
	return write(fd, str, len);
}

static int do_write(int tid, int fd, void *str, struct chunk_boundary *cb){
  per_thread_stats[tid].num_io++;
	if (do_buf_io){
		assert(io_bufs[tid].size + cb->right-cb->left < IO_BUF_SIZE);
		memcpy(io_bufs[tid].buf, (uint8_t*)str+cb->left, cb->right-cb->left);
		io_bufs[tid].size += cb->right-cb->left;
		return 0;
	}else{
    pthread_mutex_lock(&io_lock);
		uint64_t start = time_nsec(), end;
		uint64_t offset  = lseek(fd, 0, SEEK_CUR);
		uint32_t len = 0;
		if (offset >= MAX_FILE_SIZE){
			lseek(fd,0, SEEK_SET); 
		}
		len = write(fd, (uint8_t*)str+cb->left, cb->right-cb->left);
		if (len < cb->right-cb->left){
			printf("len %u size %lu\n", len, cb->right-cb->left);
		}
		end = time_nsec();
    pthread_mutex_unlock(&io_lock);
		per_thread_stats[tid].iotime+=end-start;
		return 0;
	}
}

static void sync_data_to_disk(int tid){
	if (do_buf_io){
		uint64_t end, start;
		uint64_t offset  = lseek(dump_fd, 0, SEEK_CUR);

    pthread_mutex_lock(&io_lock);
		start = time_nsec();
		if (offset >= MAX_FILE_SIZE){
			lseek(dump_fd,0, SEEK_SET); 
		}
		write(dump_fd, io_bufs[tid].buf, io_bufs[tid].size);
		io_bufs[tid].size = 0;
		end = time_nsec();
    pthread_mutex_unlock(&io_lock);
		//printf("Data sync time: %lu\n", end-start);
		per_thread_stats[tid].iotime+=end-start;
	}
	//fdatasync(dump_fd);
}


static void close_file(int fd){
	fsync(fd);
  if (io_bufs){
    for (int i=0; i< num_threads; i++)
      free(io_bufs[i].buf);
  }
  free(io_bufs);
	close(fd);
}



static int generate_microbench(struct file_struct *fs){
	struct chunk_boundary cb;
	struct fp_entry_st *fp = NULL;
	static uint64_t cid = 0;
	int seq_len = 0;
	uint64_t last_dedup_cid = 0;
	char *str = (char *)fs->map;
	uint64_t total_chunks;
	struct op_st *opp = NULL;
	char *buf = NULL;
	uint64_t buf_offset = 0;

  int tid = fs_idx(fs);
  total_chunks = next_chunk_idx[tid];

	reset_chunk_idx_in_file(tid);
	init_op_struct(&pass);
	//extract_ops(&pass, 1);
	extract_static_ops(tid, &pass, 1);
  //return 0;

	buf = (char *)calloc(fs->test_length*2, 1);

	random_data(fs->test_length/2);
	opp = next_op();
	while(next_chunk_boundary(tid, &cb)){
in_loop:
		cid = next_chunk_idx[tid]-1;
		if (opp == NULL){
			memcpy(buf+buf_offset, str+cb.left, fs->test_length-cb.left);
			buf_offset += fs->test_length-cb.left;
			break;
		}
		if (opp->chunk_id == cid){
			switch(opp->op){
				case 1: // insert
					if (opp->offset > 0){
						memcpy(buf+buf_offset, str+cb.left, opp->offset);
						buf_offset += opp->offset;
					}
					memcpy(buf+buf_offset,random_data(opp->size) , opp->size);
					buf_offset += opp->size;
					if (opp->offset < cb.right-cb.left){
						memcpy(buf+buf_offset, str+cb.left+opp->offset , cb.right-cb.left-opp->offset);
						buf_offset += cb.right-cb.left-opp->offset;
					}
					opp = next_op();
					break;
				case 2: // overwrite
					if (opp->offset > 0){
						memcpy(buf+buf_offset, str+cb.left, opp->offset);
						buf_offset += opp->offset;
					}
					memcpy(buf+buf_offset,random_data(opp->size) , opp->size);
					buf_offset += opp->size;
					assert(opp->offset + opp->size <= cb.right-cb.left);
					if (opp->offset+opp->size < cb.right-cb.left){
						memcpy(buf+buf_offset,str+cb.left+opp->offset+opp->size , cb.right-cb.left-opp->offset-opp->size);
						buf_offset += cb.right-cb.left-opp->offset-opp->size;
					}
					opp = next_op();
					break;
				case 3: // delete
					if (opp->offset > 0){
						memcpy(buf+buf_offset, str+cb.left, opp->offset);
						buf_offset += opp->offset;
					}
					if (opp->offset+opp->size < cb.right-cb.left){
						memcpy(buf+buf_offset,str+cb.left+opp->offset+opp->size , cb.right-cb.left-opp->offset-opp->size);
						buf_offset += cb.right-cb.left-opp->offset-opp->size;
					}
					opp = next_op();
					break;
				default:
					break;
			}
		}else if ( opp->chunk_id < cid){
			// do nothing, skip
			opp = next_op();
			while (opp && opp->chunk_id < cid)
				opp = next_op();
			goto in_loop;
		}else{
			memcpy(buf+buf_offset, str+cb.left, cb.right-cb.left);
			buf_offset += cb.right-cb.left;
		}
	}

	if (buf_offset){
		int fd = create_file(dir, output_file);
		dump_file(fd, buf, buf_offset);
		close_file(fd);
		printf("A file with %d bytes created\n", buf_offset);
	}

	if(random_buf)
		free(random_buf);
	free(buf);
	deinit_op_struct();
	return 0;
}

static int is_trace_mode(){
	return (fast_skip == TRACE_MODE);
}




// below are chunk functions 
//
#include "chunker-crc.h"
#include "chunker-gear.h"

static void run_cdc_with_timer(struct file_struct *fs){
	uint64_t start, end, ptime = 0;
	uint64_t start_s, end_s, stime = 0;
	phase_one_func sfunc = NULL;

  //printf("fs idx %d %p, base %p, size %d offset %d\n", fs_idx(fs), fs, fs_set, sizeof(struct file_struct), fs-fs_set);
	start = time_nsec();
	chunk_f(fs);
	end = time_nsec();
	per_thread_stats[fs_idx(fs)].serial_ns += end - start;
}


#endif

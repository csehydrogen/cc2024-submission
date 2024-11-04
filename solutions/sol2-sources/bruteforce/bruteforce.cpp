#include "AES.h"
#include <omp.h>
#include <sched.h>

double getrealtime() {
  struct timespec tp;
  clock_gettime(CLOCK_REALTIME, &tp);
  double elapsed = tp.tv_sec + tp.tv_nsec * 1e-9;
  return elapsed;
}

unsigned char plain[] = { 0x5f, 0x57, 0x3b, 0xd5, 0x70, 0x84, 0x53, 0x94, 0x9a, 0xd5, 0x07, 0x23, 0xda, 0x8d, 0x86, 0x3e };
unsigned char answer[] = { 0xe1, 0xd7, 0x0f, 0xc4, 0x52, 0xec, 0xc4, 0x40, 0x36, 0x91, 0x93, 0xe8, 0x34, 0xfb, 0xbb, 0xd6 };
unsigned char key_ref[] = {0x10, 0x32, 0x34, 0x4b, 0x72, 0xa5, 0x72, 0x79, 0x70, 0x74, 0xeb, 0x53, 0x6f, 0x6c, 0x76, 0xb5 };


int main () {
  int N = 16;
  unsigned int plainLen = N * sizeof(unsigned char); //bytes in plaintext
  unsigned char *c = NULL;  //ciphertext


  #pragma omp parallel for
  for (int k0 = 0; k0 < 256; k0++) {
    long long cnt = 0;
    double start_time = getrealtime();
    AES aes(AESKeyLength::AES_128);
    unsigned char key[] = {0x10, 0x32, 0x34, 0x4b, 0x72, 0xa5, 0x72, 0x79, 0x70, 0x74, 0xeb, 0x53, 0x6f, 0x6c, 0x76, 0xb5 };
    key[0] = (unsigned char) k0;
    for (int k5 = 0; k5 < 256; k5++) {
      key[5] = (unsigned char) k5;
      for (int k10 = 0; k10 < 256; k10++) {
        key[10] = (unsigned char) k10;
        for (int k15 = 0; k15 < 256; k15++) {
          key[15] = (unsigned char) k15;
          c = aes.EncryptECB(plain, plainLen, key);
          bool found = true;
          for (int i = 0; i < N; i++) {
            if (c[i] != answer[i]) {
              found = false;
              break;
            }
          }
          if (found) {
            printf("Found key: ");
            for (int i = 0; i < N; i++) {
              printf("%02x ", key[i]);
            }
            printf("\n");
            exit(0);
          }

          cnt++;
          if (cnt % 1000000 == 0) {
            double elapsed = getrealtime() - start_time;
            printf("(Thread %d) throughput = %.2f keys / sec\n", sched_getcpu(), cnt / elapsed);
          }
        }
      }
    }
  }

}
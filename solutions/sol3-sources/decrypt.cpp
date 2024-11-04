#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <cstdio>
#include <cstdlib>

struct chacha20_context
{
	uint32_t keystream32[16];
	size_t position;

	uint8_t key[32];
	uint8_t nonce[12];
	uint64_t counter;

	uint32_t state[16];
};

void chacha20_init_context(struct chacha20_context *ctx, uint8_t key[], uint8_t nounc[], uint64_t counter);

void chacha20_xor(struct chacha20_context *ctx, uint8_t *bytes, size_t n_bytes);

static uint32_t rotl32(uint32_t x, int n) 
{
	return (x << n) | (x >> (32 - n));
}

static uint32_t pack4(const uint8_t *a)
{
	uint32_t res = 0;
	res |= (uint32_t)a[0] << 0 * 8;
	res |= (uint32_t)a[1] << 1 * 8;
	res |= (uint32_t)a[2] << 2 * 8;
	res |= (uint32_t)a[3] << 3 * 8;
	return res;
}

static void unpack4(uint32_t src, uint8_t *dst) {
	dst[0] = (src >> 0 * 8) & 0xff;
	dst[1] = (src >> 1 * 8) & 0xff;
	dst[2] = (src >> 2 * 8) & 0xff;
	dst[3] = (src >> 3 * 8) & 0xff;
}

static void chacha20_init_block(struct chacha20_context *ctx, uint8_t key[], uint8_t nonce[])
{
	memcpy(ctx->key, key, sizeof(ctx->key));
	memcpy(ctx->nonce, nonce, sizeof(ctx->nonce));

	const uint8_t *magic_constant = (uint8_t*)"expand 32-byte k";
	ctx->state[0] = pack4(magic_constant + 0 * 4);
	ctx->state[1] = pack4(magic_constant + 1 * 4);
	ctx->state[2] = pack4(magic_constant + 2 * 4);
	ctx->state[3] = pack4(magic_constant + 3 * 4);
	ctx->state[4] = pack4(key + 0 * 4);
	ctx->state[5] = pack4(key + 1 * 4);
	ctx->state[6] = pack4(key + 2 * 4);
	ctx->state[7] = pack4(key + 3 * 4);
	ctx->state[8] = pack4(key + 4 * 4);
	ctx->state[9] = pack4(key + 5 * 4);
	ctx->state[10] = pack4(key + 6 * 4);
	ctx->state[11] = pack4(key + 7 * 4);
	// 64 bit counter initialized to zero by default.
	ctx->state[12] = 0;
	ctx->state[13] = pack4(nonce + 0 * 4);
	ctx->state[14] = pack4(nonce + 1 * 4);
	ctx->state[15] = pack4(nonce + 2 * 4);

	memcpy(ctx->nonce, nonce, sizeof(ctx->nonce));
}

static void chacha20_block_set_counter(struct chacha20_context *ctx, uint64_t counter)
{
	ctx->state[12] = (uint32_t)counter;
	ctx->state[13] = pack4(ctx->nonce + 0 * 4) + (uint32_t)(counter >> 32);
}

static void chacha20_block_next(struct chacha20_context *ctx) {
	// This is where the crazy voodoo magic happens.
	// Mix the bytes a lot and hope that nobody finds out how to undo it.
	for (int i = 0; i < 16; i++) ctx->keystream32[i] = ctx->state[i];

#define CHACHA20_QUARTERROUND(x, a, b, c, d) \
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 16); \
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 12); \
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 8); \
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 7);

	for (int i = 0; i < 10; i++) 
	{
		CHACHA20_QUARTERROUND(ctx->keystream32, 0, 4, 8, 12)
		CHACHA20_QUARTERROUND(ctx->keystream32, 1, 5, 9, 13)
		CHACHA20_QUARTERROUND(ctx->keystream32, 2, 6, 10, 14)
		CHACHA20_QUARTERROUND(ctx->keystream32, 3, 7, 11, 15)
		CHACHA20_QUARTERROUND(ctx->keystream32, 0, 5, 10, 15)
		CHACHA20_QUARTERROUND(ctx->keystream32, 1, 6, 11, 12)
		CHACHA20_QUARTERROUND(ctx->keystream32, 2, 7, 8, 13)
		CHACHA20_QUARTERROUND(ctx->keystream32, 3, 4, 9, 14)
	}

	for (int i = 0; i < 16; i++) ctx->keystream32[i] += ctx->state[i];

	uint32_t *counter = ctx->state + 12;
	// increment counter
	counter[0]++;
	if (0 == counter[0]) 
	{
		// wrap around occured, increment higher 32 bits of counter
		counter[1]++;
		// Limited to 2^64 blocks of 64 bytes each.
		// If you want to process more than 1180591620717411303424 bytes
		// you have other problems.
		// We could keep counting with counter[2] and counter[3] (nonce),
		// but then we risk reusing the nonce which is very bad.
		assert(0 != counter[1]);
	}
}

void chacha20_init_context(struct chacha20_context *ctx, uint8_t key[], uint8_t nonce[], uint64_t counter)
{
	memset(ctx, 0, sizeof(struct chacha20_context));

	chacha20_init_block(ctx, key, nonce);
	chacha20_block_set_counter(ctx, counter);

	ctx->counter = counter;
	ctx->position = 64;
}

void chacha20_xor(struct chacha20_context *ctx, uint8_t *bytes, size_t n_bytes)
{
	uint8_t *keystream8 = (uint8_t*)ctx->keystream32;
	for (size_t i = 0; i < n_bytes; i++) 
	{
		if (ctx->position >= 64) 
		{
			chacha20_block_next(ctx);
			ctx->position = 0;
		}
		bytes[i] ^= keystream8[ctx->position];
		ctx->position++;
	}
}

void dump_state(void* state, size_t nbytes) {
  for (int i = 0; i < nbytes; ++i) {
    printf("%02x ", ((uint8_t*)state)[i]);
    if (i % 16 == 15) printf("\n");
  }
  printf("\n");
}

void read_state(void* state, const char* str) {
  for (int i = 0; i < 64; i++) {
    sscanf(str + i * 3, "%02hhx", &((uint8_t*)state)[i]);
  }
}

unsigned int myseed = 0;
void mysrand(unsigned int seed) {
  myseed = seed;
}
unsigned int myrand() {
  myseed = (long)myseed * 214013L + 2531011L;
  return myseed>>16 & 0x7FFF;
}

void init_chacha_ccstyle(chacha20_context *ctx) {
  chacha20_context init_ctx;
  uint8_t empty_key[32] = {0};
  uint8_t empty_nonce[12] = {0};
  chacha20_init_context(&init_ctx, empty_key, empty_nonce, 0);
  uint8_t iv[0x28];
  for (int i = 0; i < 0x28; ++i) {
    int iVar7 = myrand();
    char x = (char)iVar7 * (i + 1);
    iv[i] = x;
  }
  myrand(); // match cryptocontext.exe implementation
  chacha20_xor(&init_ctx, iv, 0x28);
  //dump_state(iv, 0x28);

  uint8_t iv_nonce[12] = {0};
  memcpy(&iv_nonce[4], &iv[0x20], 8);
  chacha20_init_context(ctx, &iv[0], iv_nonce, 0);
  uint8_t dummy_buf[8] = {0};
  chacha20_xor(ctx, dummy_buf, 8);
  //dump_state(main_buf, 64);
}

void test_with_seed(unsigned int seed, uint8_t key[64]) {
  mysrand(seed);
  chacha20_context dummy_ctx;
  chacha20_context main_ctx[16];
  init_chacha_ccstyle(&dummy_ctx);
  for (int i = 0; i < 16; ++i) {
    init_chacha_ccstyle(&main_ctx[i]);
  }
  chacha20_xor(&main_ctx[0], key, 64);
  for (int i = 0; i < 16; ++i) {
    chacha20_xor(&main_ctx[i], key, 64);
  }
  //dump_state(key, 64);
}

bool test_jpg(uint8_t key[64]) {
  // jpg format ff d8 ff e0
  // encrypted : 74 5c d6 69
  if (
    (0xff ^ key[myrand() % 64]) == 0x74 
    && (0xd8 ^ key[myrand() % 64]) == 0x5c
    && (0xff ^ key[myrand() % 64]) == 0xd6
    && (0xe0 ^ key[myrand() % 64]) == 0x69
    ) {
    return true;
  }
  return false;
}

void decrypt_with_seed(unsigned int seed) {
  uint8_t key[64] = {0};
  test_with_seed(seed, key);

  FILE *fin = fopen("c_contest_2024_out.jpg", "rb");
  FILE *fout = fopen("c_contest_2024.jpg", "wb");
  if (!fin || !fout) {
    printf("file open failed\n");
    return;
  }
  fseek(fin, 0, SEEK_END);
  long nbytes = ftell(fin);
  fseek(fin, 0, SEEK_SET);
  uint8_t enc[nbytes];
  fread(enc, nbytes, 1, fin);
  uint8_t rand_seq[nbytes];
  for (long i = 0; i < nbytes; ++i) {
    rand_seq[i] = myrand() % 64;
  }
  uint8_t dec[nbytes];
  for (int i = 0; i < nbytes; ++i) {
    dec[i] = enc[i] ^ key[rand_seq[i]];
  }
  fwrite(dec, nbytes, 1, fout);
  fclose(fin);
  fclose(fout);
}

int main() {
  for (unsigned int i = 0; i < 1 << 12; ++i) {
    unsigned int seed = ((i & 0xf) << 4) | ((i & 0xf0) << 8) | ((i & 0xf00) << 12);
    int success = 0;
    uint8_t key[64] = {0};
    test_with_seed(seed, key);
    if (test_jpg(key)) {
      printf("seed: %08X\n", seed);
      decrypt_with_seed(seed);
      exit(0);
    }
  }

  return 0;
}
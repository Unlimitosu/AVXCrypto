#include "AVXCrypto.h"
#include <time.h>

#define XAR3(cur, pre, tmp, rk1, rk2)											\
	tmp = ADD_32(XOR32(pre, SET32(rk1)), XOR32(cur, SET32(rk2)));				\
	cur = ROR(tmp, 3);
#define XAR5(cur, pre, tmp, rk1, rk2)											\
	tmp = ADD_32(XOR32(pre, SET32(rk1)), XOR32(cur, SET32(rk2)));				\
	cur = ROR(tmp, 5);
#define XAR9(cur, pre, tmp, rk1, rk2)											\
	tmp = ADD_32(XOR32(pre, SET32(rk1)), XOR32(cur, SET32(rk2)));				\
	cur = ROR(tmp, 23);


void lea_128_avx512(uint8_t* ct, const uint8_t* pt, const uint8_t* key) {
	__m512i x0, x1, x2, x3, tmp;
	x0 = _mm512_setr_epi32(
		*((unsigned int*)pt + 0x00), *((unsigned int*)pt + 0x04), *((unsigned int*)pt + 0x08), *((unsigned int*)pt + 0x0c),
		*((unsigned int*)pt + 0x10), *((unsigned int*)pt + 0x14), *((unsigned int*)pt + 0x18), *((unsigned int*)pt + 0x1c),
		*((unsigned int*)pt + 0x20), *((unsigned int*)pt + 0x24), *((unsigned int*)pt + 0x28), *((unsigned int*)pt + 0x2c),
		*((unsigned int*)pt + 0x30), *((unsigned int*)pt + 0x34), *((unsigned int*)pt + 0x38), *((unsigned int*)pt + 0x3c));

	x1 = _mm512_setr_epi32(
		*((unsigned int*)pt + 0x01), *((unsigned int*)pt + 0x05), *((unsigned int*)pt + 0x09), *((unsigned int*)pt + 0x0d),
		*((unsigned int*)pt + 0x11), *((unsigned int*)pt + 0x15), *((unsigned int*)pt + 0x19), *((unsigned int*)pt + 0x1d),
		*((unsigned int*)pt + 0x21), *((unsigned int*)pt + 0x25), *((unsigned int*)pt + 0x29), *((unsigned int*)pt + 0x2d),
		*((unsigned int*)pt + 0x31), *((unsigned int*)pt + 0x35), *((unsigned int*)pt + 0x39), *((unsigned int*)pt + 0x3d));

	x2 = _mm512_setr_epi32(
		*((unsigned int*)pt + 0x02), *((unsigned int*)pt + 0x06), *((unsigned int*)pt + 0x0a), *((unsigned int*)pt + 0x0e),
		*((unsigned int*)pt + 0x12), *((unsigned int*)pt + 0x16), *((unsigned int*)pt + 0x1a), *((unsigned int*)pt + 0x1e),
		*((unsigned int*)pt + 0x22), *((unsigned int*)pt + 0x26), *((unsigned int*)pt + 0x2a), *((unsigned int*)pt + 0x2e),
		*((unsigned int*)pt + 0x32), *((unsigned int*)pt + 0x36), *((unsigned int*)pt + 0x3a), *((unsigned int*)pt + 0x3e));

	x3 = _mm512_setr_epi32(
		*((unsigned int*)pt + 0x03), *((unsigned int*)pt + 0x07), *((unsigned int*)pt + 0x0b), *((unsigned int*)pt + 0x0f),
		*((unsigned int*)pt + 0x13), *((unsigned int*)pt + 0x17), *((unsigned int*)pt + 0x1b), *((unsigned int*)pt + 0x1f),
		*((unsigned int*)pt + 0x23), *((unsigned int*)pt + 0x27), *((unsigned int*)pt + 0x2b), *((unsigned int*)pt + 0x2f),
		*((unsigned int*)pt + 0x33), *((unsigned int*)pt + 0x37), *((unsigned int*)pt + 0x3b), *((unsigned int*)pt + 0x3f));

	XAR3(x3, x2, tmp, key[4], key[5]);
	XAR5(x2, x1, tmp, key[2], key[3]);
	XAR9(x1, x0, tmp, key[0], key[1]);
	XAR3(x0, x3, tmp, key[10], key[11]);
	XAR5(x3, x2, tmp, key[8], key[9]);
	XAR9(x2, x1, tmp, key[6], key[7]);
	XAR3(x1, x0, tmp, key[16], key[17]);
	XAR5(x0, x3, tmp, key[14], key[15]);
	XAR9(x3, x2, tmp, key[12], key[13]);
	XAR3(x2, x1, tmp, key[22], key[23]);
	XAR5(x1, x0, tmp, key[20], key[21]);
	XAR9(x0, x3, tmp, key[18], key[19]);

	XAR3(x3, x2, tmp, key[28], key[29]);
	XAR5(x2, x1, tmp, key[26], key[27]);
	XAR9(x1, x0, tmp, key[24], key[25]);
	XAR3(x0, x3, tmp, key[34], key[35]);
	XAR5(x3, x2, tmp, key[32], key[33]);
	XAR9(x2, x1, tmp, key[30], key[31]);
	XAR3(x1, x0, tmp, key[40], key[41]);
	XAR5(x0, x3, tmp, key[38], key[39]);
	XAR9(x3, x2, tmp, key[36], key[37]);
	XAR3(x2, x1, tmp, key[46], key[47]);
	XAR5(x1, x0, tmp, key[44], key[45]);
	XAR9(x0, x3, tmp, key[42], key[43]);

	XAR3(x3, x2, tmp, key[52], key[53]);
	XAR5(x2, x1, tmp, key[50], key[51]);
	XAR9(x1, x0, tmp, key[48], key[49]);
	XAR3(x0, x3, tmp, key[58], key[59]);
	XAR5(x3, x2, tmp, key[56], key[57]);
	XAR9(x2, x1, tmp, key[54], key[55]);
	XAR3(x1, x0, tmp, key[64], key[65]);
	XAR5(x0, x3, tmp, key[62], key[63]);
	XAR9(x3, x2, tmp, key[60], key[61]);
	XAR3(x2, x1, tmp, key[70], key[71]);
	XAR5(x1, x0, tmp, key[68], key[69]);
	XAR9(x0, x3, tmp, key[66], key[67]);

	XAR3(x3, x2, tmp, key[76], key[77]);
	XAR5(x2, x1, tmp, key[74], key[75]);
	XAR9(x1, x0, tmp, key[72], key[73]);
	XAR3(x0, x3, tmp, key[82], key[83]);
	XAR5(x3, x2, tmp, key[80], key[81]);
	XAR9(x2, x1, tmp, key[78], key[79]);
	XAR3(x1, x0, tmp, key[88], key[89]);
	XAR5(x0, x3, tmp, key[86], key[87]);
	XAR9(x3, x2, tmp, key[84], key[85]);
	XAR3(x2, x1, tmp, key[94], key[95]);
	XAR5(x1, x0, tmp, key[92], key[93]);
	XAR9(x0, x3, tmp, key[90], key[91]);

	XAR3(x3, x2, tmp, key[100], key[101]);
	XAR5(x2, x1, tmp, key[98], key[99]);
	XAR9(x1, x0, tmp, key[96], key[97]);
	XAR3(x0, x3, tmp, key[106], key[107]);
	XAR5(x3, x2, tmp, key[104], key[105]);
	XAR9(x2, x1, tmp, key[102], key[103]);
	XAR3(x1, x0, tmp, key[112], key[113]);
	XAR5(x0, x3, tmp, key[110], key[111]);
	XAR9(x3, x2, tmp, key[108], key[109]);
	XAR3(x2, x1, tmp, key[118], key[119]);
	XAR5(x1, x0, tmp, key[116], key[117]);
	XAR9(x0, x3, tmp, key[114], key[115]);

	XAR3(x3, x2, tmp, key[124], key[125]);
	XAR5(x2, x1, tmp, key[122], key[123]);
	XAR9(x1, x0, tmp, key[120], key[121]);
	XAR3(x0, x3, tmp, key[130], key[131]);
	XAR5(x3, x2, tmp, key[128], key[129]);
	XAR9(x2, x1, tmp, key[126], key[127]);
	XAR3(x1, x0, tmp, key[136], key[137]);
	XAR5(x0, x3, tmp, key[134], key[135]);
	XAR9(x3, x2, tmp, key[132], key[133]);
	XAR3(x2, x1, tmp, key[142], key[143]);
	XAR5(x1, x0, tmp, key[140], key[141]);
	XAR9(x0, x3, tmp, key[138], key[139]);
}


void test() {
	uint8_t pt[512] = { 0, };
	uint8_t ct[512] = { 0, };
	uint8_t rk[128] = { 0, };
	uint8_t pt16[512] = { 0, };
	uint8_t ct16[512] = { 0, };
	uint8_t mk[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	uint64_t start, end;

	srand(time(NULL));

	//!plaintext setting
	for (int i = 0; i < 64; i++) {
		pt[8 * i + 0] = 0x00;
		pt[8 * i + 1] = 0x11;
		pt[8 * i + 2] = 0x22;
		pt[8 * i + 3] = 0x33;
		pt[8 * i + 4] = 0x44;
		pt[8 * i + 5] = 0x55;
		pt[8 * i + 6] = 0x66;
		pt[8 * i + 7] = 0x77;
	}

	for (int i = 0; i < 32; i++) {
		pt16[16 * i + 0] = 0x00;
		pt16[16 * i + 1] = 0x11;
		pt16[16 * i + 2] = 0x22;
		pt16[16 * i + 3] = 0x33;
		pt16[16 * i + 4] = 0x44;
		pt16[16 * i + 5] = 0x55;
		pt16[16 * i + 6] = 0x66;
		pt16[16 * i + 7] = 0x77;
		pt16[16 * i + 8] = 0x88;
		pt16[16 * i + 9] = 0x99;
		pt16[16 * i + 10] = 0xaa;
		pt16[16 * i + 11] = 0xbb;
		pt16[16 * i + 12] = 0xcc;
		pt16[16 * i + 13] = 0xdd;
		pt16[16 * i + 14] = 0xee;
		pt16[16 * i + 15] = 0xff;
	}

	uint64_t cycle1 = 0;
	for (int i = 0; i < 10000; i++) {
		start = cpucycles();
		lea_128_avx512(ct, pt, rk);
		end = cpucycles();
		cycle1 += end - start;
	}
	printf("Cycle AVX-512 CHAM64/128 cpb= %lf\n", ((float)(cycle1) / (10000 * 32)));

}


int main() {
	test();

	return 0;
}

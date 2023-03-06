#include "AVXCrypto.h"

__int64 cpucycles() {
	return __rdtsc();
}

void print_block(uint8_t* state, int len, int cutlen) {
	for (int i = 0; i < len; i++) {
		printf("%02X ", state[i]);
		if ((i + 1) % cutlen == 0) printf("\n");
	} printf("\n");
}

void HIGHT_genT(__m512i* T) {
	//1bit shifting Masking
	T[0] = _mm512_set1_epi16(0x7F7F);
	T[1] = _mm512_set1_epi16(0x8080);

	//2bit shifting Masking
	T[2] = _mm512_set1_epi16(0x3F3F);
	T[3] = _mm512_set1_epi16(0xC0C0);

	//3bit shifting Masking
	T[4] = _mm512_set1_epi16(0x1F1F);
	T[5] = _mm512_set1_epi16(0xE0E0);

	//4bit shifting Masking
	T[6] = _mm512_set1_epi16(0x0F0F);
	T[7] = _mm512_set1_epi16(0xF0F0);

	//5bit shifting Masking
	T[8] = _mm512_set1_epi16(0x0707);
	T[9] = _mm512_set1_epi16(0xF8F8);

	//6bit shifting Masking
	T[10] = _mm512_set1_epi16(0x0303);
	T[11] = _mm512_set1_epi16(0xFCFC);

	//7bit shifting Masking
	T[12] = _mm512_set1_epi16(0x0101);
	T[13] = _mm512_set1_epi16(0xFEFE);
}
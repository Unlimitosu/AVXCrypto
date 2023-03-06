#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <immintrin.h>
#include <Windows.h>

typedef unsigned char	   uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int	   uint32_t;
typedef unsigned long long uint64_t;

#define LOAD(x)			(_mm512_loadu_si512((__m512*)(x))))
#define STORE(x, y)		(_mm512_storeu_si512((__m512*)(x), y))
#define XOR512(x, y)	(_mm512_xor_si512(x, y))
#define ADD8(x, y)		(_mm512_add_epi8(x, y))
#define ADD16(x, y)		(_mm512_add_epi16((x), (y)))
#define SET8(x)			(_mm512_set1_epi8(x))
#define SET16(x)		(_mm512_set1_epi16(x))
#define SET32(x)		(_mm512_set1_epi32(x))
#define LSHIFT(x, n)	(_mm512_slli_epi64(x, n))
#define RSHIFT(x, n)	(_mm512_srli_epi64(x, n))

//! Rotate n-bit using T1, T2
#define ROL_epi8(T1, T2, state, n)	_mm512_or_si512(_mm512_slli_epi16(_mm512_and_si512(T1, state), n), _mm512_srli_epi16(_mm512_and_si512(T2, state), 8-n))
#define ROL_16(x ,n)				(((x)<<(n))^((x)>>(16-n)))
#define ROLN(x, n)					(_mm512_or_si512(_mm512_slli_epi16(x, n), _mm512_srli_epi16(x, 16-n)))

#define AVX512_BLOCKSIZE	512
#define HIGHT_ROUNDNUM		32
#define CHAM64_128ROUNDNUM  80

__int64 cpucycles();
void HIGHT_genT(__m512i* T); 
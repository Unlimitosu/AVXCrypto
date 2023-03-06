#include "AVXCrypto.h"
#include <time.h>

#define ROL32(x, y) (_mm512_rol_epi32(x, y))
#define ADD32(x, y) (_mm512_add_epi32(x, y))

static const size_t BLOCKSIZE_64       = 8;
static const size_t CHAM_64_128_ROUNDS = 88;


/*
    @details      bitwise rotation to 16, 32-bit size variable. rol refers to rotation left, and ror refers to rotation right.
    @param value  variable to rotate
    @param rot    determine how much rotate
    @return       rotated value
*/
static inline uint16_t ror16(uint16_t value, size_t rot) {
    return (value >> rot) | (value << (16 - rot));
}

static inline uint16_t rol16(uint16_t value, size_t rot) {
    return (value << rot) | (value >> (16 - rot));
}

static inline uint32_t rol32(uint32_t value, size_t rot) {
    return (value << rot) | (value >> (32 - rot));
}


/*
    @details    key generation function of CHAM-64/128, CHAM-128/256
    @param rks  round key
    @param mk   master key
    @return     None
*/
void cham_64_128_keygen(uint8_t* rks, const uint8_t* mk) {
    const uint16_t* key = (uint16_t*)mk;
    uint16_t* rk = (uint16_t*)rks;
    for (size_t i = 0; i < 8; ++i) {
        rk[i] = key[i] ^ rol16(key[i], 1);
        rk[(i + 8) ^ (0x1)] = rk[i] ^ rol16(key[i], 11);
        rk[i] ^= rol16(key[i], 8);
    }
}


void cham_128_256_keygen(uint8_t* rks, const uint8_t* mk) {
    const uint32_t* key = (uint32_t*)mk;
    uint32_t* rk = (uint32_t*)rks;

    for (size_t i = 0; i < 8; ++i) {
        rk[i] = key[i] ^ rol32(key[i], 1);
        rk[(i + 8) ^ (0x1)] = rk[i] ^ rol32(key[i], 11);
        rk[i] ^= rol32(key[i], 8);
    }
}


/*
    @details    CHAM-128 parallel encryption using AVX-512 instructions
    @param out  ciphertext
    @param in   plaintext
    @param RK   Round Key
    @return     None
*/
void cham_64_128_avx512(uint8_t* out, uint8_t* in, const uint8_t* RK) {

    const uint16_t* rk = (uint16_t*)RK;
    __m512i pt[4];
    __m512i _rc = _mm512_set1_epi16(0x0000);
    __m512i _one = SET16(0x0001);

    pt[0] = _mm512_setr_epi16(
        *((uint16_t*)in + 0x00), *((uint16_t*)in + 0x04), *((uint16_t*)in + 0x08), *((uint16_t*)in + 0x0c),
        *((uint16_t*)in + 0x10), *((uint16_t*)in + 0x14), *((uint16_t*)in + 0x18), *((uint16_t*)in + 0x1c),
        *((uint16_t*)in + 0x20), *((uint16_t*)in + 0x24), *((uint16_t*)in + 0x28), *((uint16_t*)in + 0x2c),
        *((uint16_t*)in + 0x30), *((uint16_t*)in + 0x34), *((uint16_t*)in + 0x38), *((uint16_t*)in + 0x3c),
        *((uint16_t*)in + 0x40), *((uint16_t*)in + 0x44), *((uint16_t*)in + 0x48), *((uint16_t*)in + 0x4c),
        *((uint16_t*)in + 0x50), *((uint16_t*)in + 0x54), *((uint16_t*)in + 0x58), *((uint16_t*)in + 0x5c),
        *((uint16_t*)in + 0x60), *((uint16_t*)in + 0x64), *((uint16_t*)in + 0x68), *((uint16_t*)in + 0x6c),
        *((uint16_t*)in + 0x70), *((uint16_t*)in + 0x74), *((uint16_t*)in + 0x78), *((uint16_t*)in + 0x7c));

    pt[1] = _mm512_setr_epi16(
        *((uint16_t*)in + 0x01), *((uint16_t*)in + 0x05), *((uint16_t*)in + 0x09), *((uint16_t*)in + 0x0d),
        *((uint16_t*)in + 0x11), *((uint16_t*)in + 0x15), *((uint16_t*)in + 0x19), *((uint16_t*)in + 0x1d),
        *((uint16_t*)in + 0x21), *((uint16_t*)in + 0x25), *((uint16_t*)in + 0x29), *((uint16_t*)in + 0x2d),
        *((uint16_t*)in + 0x31), *((uint16_t*)in + 0x35), *((uint16_t*)in + 0x39), *((uint16_t*)in + 0x3d),
        *((uint16_t*)in + 0x41), *((uint16_t*)in + 0x45), *((uint16_t*)in + 0x49), *((uint16_t*)in + 0x4d),
        *((uint16_t*)in + 0x51), *((uint16_t*)in + 0x55), *((uint16_t*)in + 0x59), *((uint16_t*)in + 0x5d),
        *((uint16_t*)in + 0x61), *((uint16_t*)in + 0x65), *((uint16_t*)in + 0x69), *((uint16_t*)in + 0x6d),
        *((uint16_t*)in + 0x71), *((uint16_t*)in + 0x75), *((uint16_t*)in + 0x79), *((uint16_t*)in + 0x7d));

    pt[2] = _mm512_setr_epi16(
        *((uint16_t*)in + 0x02), *((uint16_t*)in + 0x06), *((uint16_t*)in + 0x0a), *((uint16_t*)in + 0x0e),
        *((uint16_t*)in + 0x12), *((uint16_t*)in + 0x16), *((uint16_t*)in + 0x1a), *((uint16_t*)in + 0x1e),
        *((uint16_t*)in + 0x22), *((uint16_t*)in + 0x26), *((uint16_t*)in + 0x2a), *((uint16_t*)in + 0x2e),
        *((uint16_t*)in + 0x32), *((uint16_t*)in + 0x36), *((uint16_t*)in + 0x3a), *((uint16_t*)in + 0x3e),
        *((uint16_t*)in + 0x42), *((uint16_t*)in + 0x46), *((uint16_t*)in + 0x4a), *((uint16_t*)in + 0x4e),
        *((uint16_t*)in + 0x52), *((uint16_t*)in + 0x56), *((uint16_t*)in + 0x5a), *((uint16_t*)in + 0x5e),
        *((uint16_t*)in + 0x62), *((uint16_t*)in + 0x66), *((uint16_t*)in + 0x6a), *((uint16_t*)in + 0x6e),
        *((uint16_t*)in + 0x72), *((uint16_t*)in + 0x76), *((uint16_t*)in + 0x7a), *((uint16_t*)in + 0x7e));

    pt[3] = _mm512_setr_epi16(
        *((uint16_t*)in + 0x03), *((uint16_t*)in + 0x07), *((uint16_t*)in + 0x0b), *((uint16_t*)in + 0x0f),
        *((uint16_t*)in + 0x13), *((uint16_t*)in + 0x17), *((uint16_t*)in + 0x1b), *((uint16_t*)in + 0x1f),
        *((uint16_t*)in + 0x23), *((uint16_t*)in + 0x27), *((uint16_t*)in + 0x2b), *((uint16_t*)in + 0x2f),
        *((uint16_t*)in + 0x33), *((uint16_t*)in + 0x37), *((uint16_t*)in + 0x3b), *((uint16_t*)in + 0x3f),
        *((uint16_t*)in + 0x43), *((uint16_t*)in + 0x47), *((uint16_t*)in + 0x4b), *((uint16_t*)in + 0x4f),
        *((uint16_t*)in + 0x53), *((uint16_t*)in + 0x57), *((uint16_t*)in + 0x5b), *((uint16_t*)in + 0x5f),
        *((uint16_t*)in + 0x63), *((uint16_t*)in + 0x67), *((uint16_t*)in + 0x6b), *((uint16_t*)in + 0x6f),
        *((uint16_t*)in + 0x73), *((uint16_t*)in + 0x77), *((uint16_t*)in + 0x7b), *((uint16_t*)in + 0x7f));

    for (int i = 0; i < 88; i += 8) {
        pt[0] = ROLN(ADD16((XOR512(pt[0], _rc)), XOR512(ROLN(pt[1], 1), SET16(rk[(i + 0) % 16]))), 8);
        _rc = ADD16(_rc, _one);
        pt[1] = ROLN(ADD16((XOR512(pt[1], _rc)), XOR512(ROLN(pt[2], 8), SET16(rk[(i + 1) % 16]))), 1);
        _rc = ADD16(_rc, _one);
        pt[2] = ROLN(ADD16((XOR512(pt[2], _rc)), XOR512(ROLN(pt[3], 1), SET16(rk[(i + 2) % 16]))), 8);
        _rc = ADD16(_rc, _one);
        pt[3] = ROLN(ADD16((XOR512(pt[3], _rc)), XOR512(ROLN(pt[0], 8), SET16(rk[(i + 3) % 16]))), 1);
        _rc = ADD16(_rc, _one);

        pt[0] = ROLN(ADD16((XOR512(pt[0], _rc)), XOR512(ROLN(pt[1], 1), SET16(rk[(i + 4) % 16]))), 8);
        _rc = ADD16(_rc, _one);
        pt[1] = ROLN(ADD16((XOR512(pt[1], _rc)), XOR512(ROLN(pt[2], 8), SET16(rk[(i + 5) % 16]))), 1);
        _rc = ADD16(_rc, _one);
        pt[2] = ROLN(ADD16((XOR512(pt[2], _rc)), XOR512(ROLN(pt[3], 1), SET16(rk[(i + 6) % 16]))), 8);
        _rc = ADD16(_rc, _one);
        pt[3] = ROLN(ADD16((XOR512(pt[3], _rc)), XOR512(ROLN(pt[0], 8), SET16(rk[(i + 7) % 16]))), 1);
        _rc = ADD16(_rc, _one);
    }

    _mm512_storeu_si512((__m512i*)(out), pt[0]);
    _mm512_storeu_si512((__m512i*)(out + 64), pt[1]);
    _mm512_storeu_si512((__m512i*)(out + 128), pt[2]);
    _mm512_storeu_si512((__m512i*)(out + 192), pt[3]);
}


/*
    @details    CHAM-256 parallel encryption using AVX-512 instructions
    @param out  ciphertext
    @param in   plaintext
    @param RK   Round Key
    @return     None
*/
void cham_128_256_avx512(uint8_t* out, uint8_t* in, const uint8_t* RK) {
    __m512i x0, x1, x2, x3, _rc, tmp;
    x0 = _mm512_setr_epi32(
        *((unsigned int*)in + 0x00), *((unsigned int*)in + 0x04), *((unsigned int*)in + 0x08), *((unsigned int*)in + 0x0c),
        *((unsigned int*)in + 0x10), *((unsigned int*)in + 0x14), *((unsigned int*)in + 0x18), *((unsigned int*)in + 0x1c),
        *((unsigned int*)in + 0x20), *((unsigned int*)in + 0x24), *((unsigned int*)in + 0x28), *((unsigned int*)in + 0x2c),
        *((unsigned int*)in + 0x30), *((unsigned int*)in + 0x34), *((unsigned int*)in + 0x38), *((unsigned int*)in + 0x3c));

    x1 = _mm512_setr_epi32(
        *((unsigned int*)in + 0x01), *((unsigned int*)in + 0x05), *((unsigned int*)in + 0x09), *((unsigned int*)in + 0x0d),
        *((unsigned int*)in + 0x11), *((unsigned int*)in + 0x15), *((unsigned int*)in + 0x19), *((unsigned int*)in + 0x1d),
        *((unsigned int*)in + 0x21), *((unsigned int*)in + 0x25), *((unsigned int*)in + 0x29), *((unsigned int*)in + 0x2d),
        *((unsigned int*)in + 0x31), *((unsigned int*)in + 0x35), *((unsigned int*)in + 0x39), *((unsigned int*)in + 0x3d));

    x2 = _mm512_setr_epi32(
        *((unsigned int*)in + 0x02), *((unsigned int*)in + 0x06), *((unsigned int*)in + 0x0a), *((unsigned int*)in + 0x0e),
        *((unsigned int*)in + 0x12), *((unsigned int*)in + 0x16), *((unsigned int*)in + 0x1a), *((unsigned int*)in + 0x1e),
        *((unsigned int*)in + 0x22), *((unsigned int*)in + 0x26), *((unsigned int*)in + 0x2a), *((unsigned int*)in + 0x2e),
        *((unsigned int*)in + 0x32), *((unsigned int*)in + 0x36), *((unsigned int*)in + 0x3a), *((unsigned int*)in + 0x3e));

    x3 = _mm512_setr_epi32(
        *((unsigned int*)in + 0x03), *((unsigned int*)in + 0x07), *((unsigned int*)in + 0x0b), *((unsigned int*)in + 0x0f),
        *((unsigned int*)in + 0x13), *((unsigned int*)in + 0x17), *((unsigned int*)in + 0x1b), *((unsigned int*)in + 0x1f),
        *((unsigned int*)in + 0x23), *((unsigned int*)in + 0x27), *((unsigned int*)in + 0x2b), *((unsigned int*)in + 0x2f),
        *((unsigned int*)in + 0x33), *((unsigned int*)in + 0x37), *((unsigned int*)in + 0x3b), *((unsigned int*)in + 0x3f));

    const uint32_t* rk = (const uint32_t*)RK;
    __m512i _one = SET32(1);
    _rc = _mm512_set1_epi32(0);

    for (int i = 0; i < 120; i += 8) {
        x0 = ROL32(ADD32(XOR512(ROL32(x1, 1), SET32(rk[(i + 0) % 16])), XOR512(x0, _rc)), 8);
        _rc = _mm512_add_epi32(_rc, _one);

        x1 = ROL32(ADD32(XOR512(ROL32(x2, 8), SET32(rk[(i + 1) % 16])), XOR512(x1, _rc)), 1);
        _rc = _mm512_add_epi32(_rc, _one);

        x2 = ROL32(ADD32(XOR512(ROL32(x3, 1), SET32(rk[(i + 2) % 16])), XOR512(x2, _rc)), 8);
        _rc = _mm512_add_epi32(_rc, _one);

        x3 = ROL32(ADD32(XOR512(ROL32(x0, 8), SET32(rk[(i + 3) % 16])), XOR512(x3, _rc)), 1);
        _rc = _mm512_add_epi32(_rc, _one);

        x0 = ROL32(ADD32(XOR512(ROL32(x1, 1), SET32(rk[(i + 4) % 16])), XOR512(x0, _rc)), 8);
        _rc = _mm512_add_epi32(_rc, _one);

        x1 = ROL32(ADD32(XOR512(ROL32(x2, 8), SET32(rk[(i + 5) % 16])), XOR512(x1, _rc)), 1);
        _rc = _mm512_add_epi32(_rc, _one);

        x2 = ROL32(ADD32(XOR512(ROL32(x3, 1), SET32(rk[(i + 6) % 16])), XOR512(x2, _rc)), 8);
        _rc = _mm512_add_epi32(_rc, _one);

        x3 = ROL32(ADD32(XOR512(ROL32(x0, 8), SET32(rk[(i + 7) % 16])), XOR512(x3, _rc)), 1);
        _rc = _mm512_add_epi32(_rc, _one);
    }
    _mm512_storeu_si512((__m512i*)(out), x0);
    _mm512_storeu_si512((__m512i*)(out + 64), x1);
    _mm512_storeu_si512((__m512i*)(out + 128), x2);
    _mm512_storeu_si512((__m512i*)(out + 192), x3);
}


/*
    @details    test function with measuring performance
    @return     None
*/
void test_cham() {
    uint8_t pt[512]     = { 0, };
    uint8_t ct[512]     = { 0, };
    uint8_t rk[128]     = { 0, };
    uint8_t pt16[512]   = { 0, };
    uint8_t ct16[512]   = { 0, };
    uint8_t mk[16]      = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
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

    cham_64_128_keygen(rk, mk);
    printf("\n-------------------------\n");
    uint64_t cycle1 = 0;
    for (int i = 0; i < 10000; i++) {
        start = cpucycles();
        cham_64_128_avx512(ct, pt, rk);
        end = cpucycles();
        cycle1 += end - start;
    }
    printf("Cycle AVX-512 CHAM64/128 cpb= %lf\n", ((float)(cycle1) / (10000 * 32)));

    cham_128_256_keygen(rk, mk);
    cycle1 = 0;
    for (int i = 0; i < 10000; i++) {
        start = cpucycles();
        cham_128_256_avx512(ct16, pt16, rk);
        end = cpucycles();
        cycle1 += end - start;
    }
    printf("\nCycle AVX-512 CHAM64/128 cpb= %lf\n", ((float)(cycle1) / (10000 * 16)));
}

#include "AVXCrypto.h"


static uint8_t DELTA[128] = {
		0x5A,0x6D,0x36,0x1B,0x0D,0x06,0x03,0x41,
		0x60,0x30,0x18,0x4C,0x66,0x33,0x59,0x2C,
		0x56,0x2B,0x15,0x4A,0x65,0x72,0x39,0x1C,
		0x4E,0x67,0x73,0x79,0x3C,0x5E,0x6F,0x37,
		0x5B,0x2D,0x16,0x0B,0x05,0x42,0x21,0x50,
		0x28,0x54,0x2A,0x55,0x6A,0x75,0x7A,0x7D,
		0x3E,0x5F,0x2F,0x17,0x4B,0x25,0x52,0x29,
		0x14,0x0A,0x45,0x62,0x31,0x58,0x6C,0x76,
		0x3B,0x1D,0x0E,0x47,0x63,0x71,0x78,0x7C,
		0x7E,0x7F,0x3F,0x1F,0x0F,0x07,0x43,0x61,
		0x70,0x38,0x5C,0x6E,0x77,0x7B,0x3D,0x1E,
		0x4F,0x27,0x53,0x69,0x34,0x1A,0x4D,0x26,
		0x13,0x49,0x24,0x12,0x09,0x04,0x02,0x01,
		0x40,0x20,0x10,0x08,0x44,0x22,0x11,0x48,
		0x64,0x32,0x19,0x0C,0x46,0x23,0x51,0x68,
		0x74,0x3A,0x5D,0x2E,0x57,0x6B,0x35,0x5A };

/*
    @details    key generation function of HIGHT
    @param rks  round key
    @param mk   master key
    @return     None
*/
void AVX512_HIGHT_RoundkeyGen(uint8_t* rks, uint8_t* mk) {

    //! Generate WK
    for (int i = 0; i < 4; i++) {
        rks[i] = mk[i + 12];
        rks[i + 4] = mk[i];
    }

    //! Generate SK
    //! Use &7 instead of %8
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            rks[8 + 16 * i + j] = (mk[(j - i) & 7] + DELTA[16 * i + j]) & 0xff;
            rks[16 + 16 * i + j] = (mk[((j - i) & 7) + 8] + DELTA[16 * i + j + 8]) & 0xff;
        }
    }
}


/*
    @details    HIGHT parallel encryption using AVX-512 instructions
    @param out  ciphertext
    @param in   plaintext
    @param RK   Round Key
    @param T    Table for masking
    @return     None
*/
void hight_avx512(uint8_t* in, uint8_t* out, uint8_t* RK, __m512i* T) {
    uint8_t buf[AVX512_BLOCKSIZE];
    __m512i PT[8];
    __m512i tmp0, tmp1, tmp2, tmp3;
    __m512i FPT0, FPT2, FPT4, FPT6;

    //! Set Plaintext
    memcpy(buf, in, AVX512_BLOCKSIZE);
    for (int i = 0; i < 8; i++) {
        PT[i] = _mm512_loadu_si512(buf + i * 64);
    }

    PT[0] = _mm512_setr_epi8(
        *((uint8_t*)in + 0x00),  *((uint8_t*)in + 0x08),  *((uint8_t*)in + 0x10),  *((uint8_t*)in + 0x18),
        *((uint8_t*)in + 0x20),  *((uint8_t*)in + 0x28),  *((uint8_t*)in + 0x30),  *((uint8_t*)in + 0x38),
        *((uint8_t*)in + 0x40),  *((uint8_t*)in + 0x48),  *((uint8_t*)in + 0x50),  *((uint8_t*)in + 0x58),
        *((uint8_t*)in + 0x60),  *((uint8_t*)in + 0x68),  *((uint8_t*)in + 0x70),  *((uint8_t*)in + 0x78),
        *((uint8_t*)in + 0x80),  *((uint8_t*)in + 0x88),  *((uint8_t*)in + 0x90),  *((uint8_t*)in + 0x98),
        *((uint8_t*)in + 0xa0),  *((uint8_t*)in + 0xa8),  *((uint8_t*)in + 0xb0),  *((uint8_t*)in + 0xb8),
        *((uint8_t*)in + 0xc0),  *((uint8_t*)in + 0xc8),  *((uint8_t*)in + 0xd0),  *((uint8_t*)in + 0xd8),
        *((uint8_t*)in + 0xe0),  *((uint8_t*)in + 0xe8),  *((uint8_t*)in + 0xf0),  *((uint8_t*)in + 0xf8),
        *((uint8_t*)in + 0x100), *((uint8_t*)in + 0x108), *((uint8_t*)in + 0x110), *((uint8_t*)in + 0x118),
        *((uint8_t*)in + 0x120), *((uint8_t*)in + 0x128), *((uint8_t*)in + 0x130), *((uint8_t*)in + 0x138),
        *((uint8_t*)in + 0x140), *((uint8_t*)in + 0x148), *((uint8_t*)in + 0x150), *((uint8_t*)in + 0x158),
        *((uint8_t*)in + 0x160), *((uint8_t*)in + 0x168), *((uint8_t*)in + 0x170), *((uint8_t*)in + 0x178),
        *((uint8_t*)in + 0x180), *((uint8_t*)in + 0x188), *((uint8_t*)in + 0x190), *((uint8_t*)in + 0x198),
        *((uint8_t*)in + 0x1a0), *((uint8_t*)in + 0x1a8), *((uint8_t*)in + 0x1b0), *((uint8_t*)in + 0x1b8),
        *((uint8_t*)in + 0x1c0), *((uint8_t*)in + 0x1c8), *((uint8_t*)in + 0x1d0), *((uint8_t*)in + 0x1d8),
        *((uint8_t*)in + 0x1e0), *((uint8_t*)in + 0x1e8), *((uint8_t*)in + 0x1f0), *((uint8_t*)in + 0x1f8));

    PT[1] = _mm512_setr_epi8(
        *((uint8_t*)in + 0x01),  *((uint8_t*)in + 0x09),  *((uint8_t*)in + 0x11),  *((uint8_t*)in + 0x19),
        *((uint8_t*)in + 0x21),  *((uint8_t*)in + 0x29),  *((uint8_t*)in + 0x31),  *((uint8_t*)in + 0x39),
        *((uint8_t*)in + 0x41),  *((uint8_t*)in + 0x49),  *((uint8_t*)in + 0x51),  *((uint8_t*)in + 0x59),
        *((uint8_t*)in + 0x61),  *((uint8_t*)in + 0x69),  *((uint8_t*)in + 0x71),  *((uint8_t*)in + 0x79),
        *((uint8_t*)in + 0x81),  *((uint8_t*)in + 0x89),  *((uint8_t*)in + 0x91),  *((uint8_t*)in + 0x99),
        *((uint8_t*)in + 0xa1),  *((uint8_t*)in + 0xa9),  *((uint8_t*)in + 0xb1),  *((uint8_t*)in + 0xb9),
        *((uint8_t*)in + 0xc1),  *((uint8_t*)in + 0xc9),  *((uint8_t*)in + 0xd1),  *((uint8_t*)in + 0xd9),
        *((uint8_t*)in + 0xe1),  *((uint8_t*)in + 0xe9),  *((uint8_t*)in + 0xf1),  *((uint8_t*)in + 0xf9),
        *((uint8_t*)in + 0x101), *((uint8_t*)in + 0x109), *((uint8_t*)in + 0x111), *((uint8_t*)in + 0x119),
        *((uint8_t*)in + 0x121), *((uint8_t*)in + 0x129), *((uint8_t*)in + 0x131), *((uint8_t*)in + 0x139),
        *((uint8_t*)in + 0x141), *((uint8_t*)in + 0x149), *((uint8_t*)in + 0x151), *((uint8_t*)in + 0x159),
        *((uint8_t*)in + 0x161), *((uint8_t*)in + 0x169), *((uint8_t*)in + 0x171), *((uint8_t*)in + 0x179),
        *((uint8_t*)in + 0x181), *((uint8_t*)in + 0x189), *((uint8_t*)in + 0x191), *((uint8_t*)in + 0x199),
        *((uint8_t*)in + 0x1a1), *((uint8_t*)in + 0x1a9), *((uint8_t*)in + 0x1b1), *((uint8_t*)in + 0x1b9),
        *((uint8_t*)in + 0x1c1), *((uint8_t*)in + 0x1c9), *((uint8_t*)in + 0x1d1), *((uint8_t*)in + 0x1d9),
        *((uint8_t*)in + 0x1e1), *((uint8_t*)in + 0x1e9), *((uint8_t*)in + 0x1f1), *((uint8_t*)in + 0x1f9));

    PT[2] = _mm512_setr_epi8(
        *((uint8_t*)in + 0x02),  *((uint8_t*)in + 0x0a),  *((uint8_t*)in + 0x12),  *((uint8_t*)in + 0x1a),
        *((uint8_t*)in + 0x22),  *((uint8_t*)in + 0x2a),  *((uint8_t*)in + 0x32),  *((uint8_t*)in + 0x3a),
        *((uint8_t*)in + 0x42),  *((uint8_t*)in + 0x4a),  *((uint8_t*)in + 0x52),  *((uint8_t*)in + 0x5a),
        *((uint8_t*)in + 0x62),  *((uint8_t*)in + 0x6a),  *((uint8_t*)in + 0x72),  *((uint8_t*)in + 0x7a),
        *((uint8_t*)in + 0x82),  *((uint8_t*)in + 0x8a),  *((uint8_t*)in + 0x92),  *((uint8_t*)in + 0x9a),
        *((uint8_t*)in + 0xa2),  *((uint8_t*)in + 0xaa),  *((uint8_t*)in + 0xb2),  *((uint8_t*)in + 0xba),
        *((uint8_t*)in + 0xc2),  *((uint8_t*)in + 0xca),  *((uint8_t*)in + 0xd2),  *((uint8_t*)in + 0xda),
        *((uint8_t*)in + 0xe2),  *((uint8_t*)in + 0xea),  *((uint8_t*)in + 0xf2),  *((uint8_t*)in + 0xfa),
        *((uint8_t*)in + 0x102), *((uint8_t*)in + 0x10a), *((uint8_t*)in + 0x112), *((uint8_t*)in + 0x11a),
        *((uint8_t*)in + 0x122), *((uint8_t*)in + 0x12a), *((uint8_t*)in + 0x132), *((uint8_t*)in + 0x13a),
        *((uint8_t*)in + 0x142), *((uint8_t*)in + 0x14a), *((uint8_t*)in + 0x152), *((uint8_t*)in + 0x15a),
        *((uint8_t*)in + 0x162), *((uint8_t*)in + 0x16a), *((uint8_t*)in + 0x172), *((uint8_t*)in + 0x17a),
        *((uint8_t*)in + 0x182), *((uint8_t*)in + 0x18a), *((uint8_t*)in + 0x192), *((uint8_t*)in + 0x19a),
        *((uint8_t*)in + 0x1a2), *((uint8_t*)in + 0x1aa), *((uint8_t*)in + 0x1b2), *((uint8_t*)in + 0x1ba),
        *((uint8_t*)in + 0x1c2), *((uint8_t*)in + 0x1ca), *((uint8_t*)in + 0x1d2), *((uint8_t*)in + 0x1da),
        *((uint8_t*)in + 0x1e2), *((uint8_t*)in + 0x1ea), *((uint8_t*)in + 0x1f2), *((uint8_t*)in + 0x1fa));

    PT[3] = _mm512_setr_epi8(
        *((uint8_t*)in + 0x03),  *((uint8_t*)in + 0x0b),  *((uint8_t*)in + 0x13),  *((uint8_t*)in + 0x1b),
        *((uint8_t*)in + 0x23),  *((uint8_t*)in + 0x2b),  *((uint8_t*)in + 0x33),  *((uint8_t*)in + 0x3b),
        *((uint8_t*)in + 0x43),  *((uint8_t*)in + 0x4b),  *((uint8_t*)in + 0x53),  *((uint8_t*)in + 0x5b),
        *((uint8_t*)in + 0x63),  *((uint8_t*)in + 0x6b),  *((uint8_t*)in + 0x73),  *((uint8_t*)in + 0x7b),
        *((uint8_t*)in + 0x83),  *((uint8_t*)in + 0x8b),  *((uint8_t*)in + 0x93),  *((uint8_t*)in + 0x9b),
        *((uint8_t*)in + 0xa3),  *((uint8_t*)in + 0xab),  *((uint8_t*)in + 0xb3),  *((uint8_t*)in + 0xbb),
        *((uint8_t*)in + 0xc3),  *((uint8_t*)in + 0xcb),  *((uint8_t*)in + 0xd3),  *((uint8_t*)in + 0xdb),
        *((uint8_t*)in + 0xe3),  *((uint8_t*)in + 0xeb),  *((uint8_t*)in + 0xf3),  *((uint8_t*)in + 0xfb),
        *((uint8_t*)in + 0x103), *((uint8_t*)in + 0x10b), *((uint8_t*)in + 0x113), *((uint8_t*)in + 0x11b),
        *((uint8_t*)in + 0x123), *((uint8_t*)in + 0x12b), *((uint8_t*)in + 0x133), *((uint8_t*)in + 0x13b),
        *((uint8_t*)in + 0x143), *((uint8_t*)in + 0x14b), *((uint8_t*)in + 0x153), *((uint8_t*)in + 0x15b),
        *((uint8_t*)in + 0x163), *((uint8_t*)in + 0x16b), *((uint8_t*)in + 0x173), *((uint8_t*)in + 0x17b),
        *((uint8_t*)in + 0x183), *((uint8_t*)in + 0x18b), *((uint8_t*)in + 0x193), *((uint8_t*)in + 0x19b),
        *((uint8_t*)in + 0x1a3), *((uint8_t*)in + 0x1ab), *((uint8_t*)in + 0x1b3), *((uint8_t*)in + 0x1bb),
        *((uint8_t*)in + 0x1c3), *((uint8_t*)in + 0x1cb), *((uint8_t*)in + 0x1d3), *((uint8_t*)in + 0x1db),
        *((uint8_t*)in + 0x1e3), *((uint8_t*)in + 0x1eb), *((uint8_t*)in + 0x1f3), *((uint8_t*)in + 0x1fb));

    PT[4] = _mm512_setr_epi8(
        *((uint8_t*)in + 0x04),  *((uint8_t*)in + 0x0c),  *((uint8_t*)in + 0x14),  *((uint8_t*)in + 0x1c),
        *((uint8_t*)in + 0x24),  *((uint8_t*)in + 0x2c),  *((uint8_t*)in + 0x34),  *((uint8_t*)in + 0x3c),
        *((uint8_t*)in + 0x44),  *((uint8_t*)in + 0x4c),  *((uint8_t*)in + 0x54),  *((uint8_t*)in + 0x5c),
        *((uint8_t*)in + 0x64),  *((uint8_t*)in + 0x6c),  *((uint8_t*)in + 0x74),  *((uint8_t*)in + 0x7c),
        *((uint8_t*)in + 0x84),  *((uint8_t*)in + 0x8c),  *((uint8_t*)in + 0x94),  *((uint8_t*)in + 0x9c),
        *((uint8_t*)in + 0xa4),  *((uint8_t*)in + 0xac),  *((uint8_t*)in + 0xb4),  *((uint8_t*)in + 0xbc),
        *((uint8_t*)in + 0xc4),  *((uint8_t*)in + 0xcc),  *((uint8_t*)in + 0xd4),  *((uint8_t*)in + 0xdc),
        *((uint8_t*)in + 0xe4),  *((uint8_t*)in + 0xec),  *((uint8_t*)in + 0xf4),  *((uint8_t*)in + 0xfc),
        *((uint8_t*)in + 0x104), *((uint8_t*)in + 0x10c), *((uint8_t*)in + 0x114), *((uint8_t*)in + 0x11c),
        *((uint8_t*)in + 0x124), *((uint8_t*)in + 0x12c), *((uint8_t*)in + 0x134), *((uint8_t*)in + 0x13c),
        *((uint8_t*)in + 0x144), *((uint8_t*)in + 0x14c), *((uint8_t*)in + 0x154), *((uint8_t*)in + 0x15c),
        *((uint8_t*)in + 0x164), *((uint8_t*)in + 0x16c), *((uint8_t*)in + 0x174), *((uint8_t*)in + 0x17c),
        *((uint8_t*)in + 0x184), *((uint8_t*)in + 0x18c), *((uint8_t*)in + 0x194), *((uint8_t*)in + 0x19c),
        *((uint8_t*)in + 0x1a4), *((uint8_t*)in + 0x1ac), *((uint8_t*)in + 0x1b4), *((uint8_t*)in + 0x1bc),
        *((uint8_t*)in + 0x1c4), *((uint8_t*)in + 0x1cc), *((uint8_t*)in + 0x1d4), *((uint8_t*)in + 0x1dc),
        *((uint8_t*)in + 0x1e4), *((uint8_t*)in + 0x1ec), *((uint8_t*)in + 0x1f4), *((uint8_t*)in + 0x1fc));

    PT[5] = _mm512_setr_epi8(
        *((uint8_t*)in + 0x05),  *((uint8_t*)in + 0x0d),  *((uint8_t*)in + 0x15),  *((uint8_t*)in + 0x1d),
        *((uint8_t*)in + 0x25),  *((uint8_t*)in + 0x2d),  *((uint8_t*)in + 0x35),  *((uint8_t*)in + 0x3d),
        *((uint8_t*)in + 0x45),  *((uint8_t*)in + 0x4d),  *((uint8_t*)in + 0x55),  *((uint8_t*)in + 0x5d),
        *((uint8_t*)in + 0x65),  *((uint8_t*)in + 0x6d),  *((uint8_t*)in + 0x75),  *((uint8_t*)in + 0x7d),
        *((uint8_t*)in + 0x85),  *((uint8_t*)in + 0x8d),  *((uint8_t*)in + 0x95),  *((uint8_t*)in + 0x9d),
        *((uint8_t*)in + 0xa5),  *((uint8_t*)in + 0xad),  *((uint8_t*)in + 0xb5),  *((uint8_t*)in + 0xbd),
        *((uint8_t*)in + 0xc5),  *((uint8_t*)in + 0xcd),  *((uint8_t*)in + 0xd5),  *((uint8_t*)in + 0xdd),
        *((uint8_t*)in + 0xe5),  *((uint8_t*)in + 0xed),  *((uint8_t*)in + 0xf5),  *((uint8_t*)in + 0xfd),
        *((uint8_t*)in + 0x105), *((uint8_t*)in + 0x10d), *((uint8_t*)in + 0x115), *((uint8_t*)in + 0x11d),
        *((uint8_t*)in + 0x125), *((uint8_t*)in + 0x12d), *((uint8_t*)in + 0x135), *((uint8_t*)in + 0x13d),
        *((uint8_t*)in + 0x145), *((uint8_t*)in + 0x14d), *((uint8_t*)in + 0x155), *((uint8_t*)in + 0x15d),
        *((uint8_t*)in + 0x165), *((uint8_t*)in + 0x16d), *((uint8_t*)in + 0x175), *((uint8_t*)in + 0x17d),
        *((uint8_t*)in + 0x185), *((uint8_t*)in + 0x18d), *((uint8_t*)in + 0x195), *((uint8_t*)in + 0x19d),
        *((uint8_t*)in + 0x1a5), *((uint8_t*)in + 0x1ad), *((uint8_t*)in + 0x1b5), *((uint8_t*)in + 0x1bd),
        *((uint8_t*)in + 0x1c5), *((uint8_t*)in + 0x1cd), *((uint8_t*)in + 0x1d5), *((uint8_t*)in + 0x1dd),
        *((uint8_t*)in + 0x1e5), *((uint8_t*)in + 0x1ed), *((uint8_t*)in + 0x1f5), *((uint8_t*)in + 0x1fd));

    PT[6] = _mm512_setr_epi8(
        *((uint8_t*)in + 0x06),  *((uint8_t*)in + 0x0e),  *((uint8_t*)in + 0x16),  *((uint8_t*)in + 0x1e),
        *((uint8_t*)in + 0x26),  *((uint8_t*)in + 0x2e),  *((uint8_t*)in + 0x36),  *((uint8_t*)in + 0x3e),
        *((uint8_t*)in + 0x46),  *((uint8_t*)in + 0x4e),  *((uint8_t*)in + 0x56),  *((uint8_t*)in + 0x5e),
        *((uint8_t*)in + 0x66),  *((uint8_t*)in + 0x6e),  *((uint8_t*)in + 0x76),  *((uint8_t*)in + 0x7e),
        *((uint8_t*)in + 0x86),  *((uint8_t*)in + 0x8e),  *((uint8_t*)in + 0x96),  *((uint8_t*)in + 0x9e),
        *((uint8_t*)in + 0xa6),  *((uint8_t*)in + 0xae),  *((uint8_t*)in + 0xb6),  *((uint8_t*)in + 0xbe),
        *((uint8_t*)in + 0xc6),  *((uint8_t*)in + 0xce),  *((uint8_t*)in + 0xd6),  *((uint8_t*)in + 0xde),
        *((uint8_t*)in + 0xe6),  *((uint8_t*)in + 0xee),  *((uint8_t*)in + 0xf6),  *((uint8_t*)in + 0xfe),
        *((uint8_t*)in + 0x106), *((uint8_t*)in + 0x10e), *((uint8_t*)in + 0x116), *((uint8_t*)in + 0x11e),
        *((uint8_t*)in + 0x126), *((uint8_t*)in + 0x12e), *((uint8_t*)in + 0x136), *((uint8_t*)in + 0x13e),
        *((uint8_t*)in + 0x146), *((uint8_t*)in + 0x14e), *((uint8_t*)in + 0x156), *((uint8_t*)in + 0x15e),
        *((uint8_t*)in + 0x166), *((uint8_t*)in + 0x16e), *((uint8_t*)in + 0x176), *((uint8_t*)in + 0x17e),
        *((uint8_t*)in + 0x186), *((uint8_t*)in + 0x18e), *((uint8_t*)in + 0x196), *((uint8_t*)in + 0x19e),
        *((uint8_t*)in + 0x1a6), *((uint8_t*)in + 0x1ae), *((uint8_t*)in + 0x1b6), *((uint8_t*)in + 0x1be),
        *((uint8_t*)in + 0x1c6), *((uint8_t*)in + 0x1ce), *((uint8_t*)in + 0x1d6), *((uint8_t*)in + 0x1de),
        *((uint8_t*)in + 0x1e6), *((uint8_t*)in + 0x1ee), *((uint8_t*)in + 0x1f6), *((uint8_t*)in + 0x1fe));

    PT[7] = _mm512_setr_epi8(
        *((uint8_t*)in + 0x07),  *((uint8_t*)in + 0x0f),  *((uint8_t*)in + 0x17),  *((uint8_t*)in + 0x1f),
        *((uint8_t*)in + 0x27),  *((uint8_t*)in + 0x2f),  *((uint8_t*)in + 0x37),  *((uint8_t*)in + 0x3f),
        *((uint8_t*)in + 0x47),  *((uint8_t*)in + 0x4f),  *((uint8_t*)in + 0x57),  *((uint8_t*)in + 0x5f),
        *((uint8_t*)in + 0x67),  *((uint8_t*)in + 0x6f),  *((uint8_t*)in + 0x77),  *((uint8_t*)in + 0x7f),
        *((uint8_t*)in + 0x87),  *((uint8_t*)in + 0x8f),  *((uint8_t*)in + 0x97),  *((uint8_t*)in + 0x9f),
        *((uint8_t*)in + 0xa7),  *((uint8_t*)in + 0xaf),  *((uint8_t*)in + 0xb7),  *((uint8_t*)in + 0xbf),
        *((uint8_t*)in + 0xc7),  *((uint8_t*)in + 0xcf),  *((uint8_t*)in + 0xd7),  *((uint8_t*)in + 0xdf),
        *((uint8_t*)in + 0xe7),  *((uint8_t*)in + 0xef),  *((uint8_t*)in + 0xf7),  *((uint8_t*)in + 0xff),
        *((uint8_t*)in + 0x107), *((uint8_t*)in + 0x10f), *((uint8_t*)in + 0x117), *((uint8_t*)in + 0x11f),
        *((uint8_t*)in + 0x127), *((uint8_t*)in + 0x12f), *((uint8_t*)in + 0x137), *((uint8_t*)in + 0x13f),
        *((uint8_t*)in + 0x147), *((uint8_t*)in + 0x14f), *((uint8_t*)in + 0x157), *((uint8_t*)in + 0x15f),
        *((uint8_t*)in + 0x167), *((uint8_t*)in + 0x16f), *((uint8_t*)in + 0x177), *((uint8_t*)in + 0x17f),
        *((uint8_t*)in + 0x187), *((uint8_t*)in + 0x18f), *((uint8_t*)in + 0x197), *((uint8_t*)in + 0x19f),
        *((uint8_t*)in + 0x1a7), *((uint8_t*)in + 0x1af), *((uint8_t*)in + 0x1b7), *((uint8_t*)in + 0x1bf),
        *((uint8_t*)in + 0x1c7), *((uint8_t*)in + 0x1cf), *((uint8_t*)in + 0x1d7), *((uint8_t*)in + 0x1df),
        *((uint8_t*)in + 0x1e7), *((uint8_t*)in + 0x1ef), *((uint8_t*)in + 0x1f7), *((uint8_t*)in + 0x1ff));

    //! Initialization
    PT[0] = ADD8(PT[0], SET8(RK[0]));
    PT[2] = XOR512(PT[2], SET8(RK[1]));
    PT[4] = ADD8(PT[4], SET8(RK[2]));
    PT[6] = XOR512(PT[6], SET8(RK[3]));

    //! Encryption Round
    for (int i = 1; i < 32; i++) {

        FPT0 = (XOR512(XOR512(ROL_epi8(T[4], T[5], PT[0], 3), ROL_epi8(T[6], T[7], PT[0], 4)), ROL_epi8(T[10], T[11], PT[0], 6)));
        FPT2 = (XOR512(XOR512(ROL_epi8(T[0], T[1], PT[2], 1), ROL_epi8(T[2], T[3], PT[2], 2)), ROL_epi8(T[12], T[13], PT[2], 7)));
        FPT4 = (XOR512(XOR512(ROL_epi8(T[4], T[5], PT[4], 3), ROL_epi8(T[6], T[7], PT[4], 4)), ROL_epi8(T[10], T[11], PT[4], 6)));
        FPT6 = (XOR512(XOR512(ROL_epi8(T[0], T[1], PT[6], 1), ROL_epi8(T[2], T[3], PT[6], 2)), ROL_epi8(T[12], T[13], PT[6], 7)));

        tmp0 = PT[0];	tmp1 = PT[2];
        tmp2 = PT[4];	tmp3 = PT[6];

        PT[0] = XOR512(PT[7], ADD8(FPT6, SET8(RK[4 * i + 7])));
        PT[2] = ADD8(PT[1], XOR512(FPT0, SET8(RK[4 * i + 4])));
        PT[4] = XOR512(PT[3], ADD8(FPT2, SET8(RK[4 * i + 5])));
        PT[6] = ADD8(PT[5], XOR512(FPT4, SET8(RK[4 * i + 6])));

        PT[1] = tmp0;	PT[3] = tmp1;
        PT[5] = tmp2;	PT[7] = tmp3;
    }

    //! Final Round (Round 32)
    FPT0 = (XOR512(XOR512(ROL_epi8(T[4], T[5], PT[0], 3), ROL_epi8(T[6], T[7], PT[0], 4)), ROL_epi8(T[10], T[11], PT[0], 6)));
    FPT2 = (XOR512(XOR512(ROL_epi8(T[0], T[1], PT[2], 1), ROL_epi8(T[2], T[3], PT[2], 2)), ROL_epi8(T[12], T[13], PT[2], 7)));
    FPT4 = (XOR512(XOR512(ROL_epi8(T[4], T[5], PT[4], 3), ROL_epi8(T[6], T[7], PT[4], 4)), ROL_epi8(T[10], T[11], PT[4], 6)));
    FPT6 = (XOR512(XOR512(ROL_epi8(T[0], T[1], PT[6], 1), ROL_epi8(T[2], T[3], PT[6], 2)), ROL_epi8(T[12], T[13], PT[6], 7)));

    PT[1] = ADD8(PT[1], XOR512(FPT0, SET8(RK[132])));
    PT[3] = XOR512(PT[3], ADD8(FPT2, SET8(RK[133])));
    PT[5] = ADD8(PT[5], XOR512(FPT4, SET8(RK[134])));
    PT[7] = XOR512(PT[7], ADD8(FPT6, SET8(RK[135])));

    PT[0] = ADD8(PT[0], SET8(RK[4]));
    PT[2] = XOR512(PT[2], SET8(RK[5]));
    PT[4] = ADD8(PT[4], SET8(RK[6]));
    PT[6] = XOR512(PT[6], SET8(RK[7]));

    for (int i = 0; i < 8; i++) {
        _mm512_storeu_si512((__m512i*)(out + i * 64), PT[i]);
    }
}


/*
    @details    test function with measuring performance
    @return     None
*/
void test_hight() {
    uint8_t pbData[8] = {  0xD7, 0x6D, 0x0D, 0x18, 0x32, 0x7E, 0xC5, 0x62 };
	uint8_t mk[16]    = {  0x88, 0xE3, 0x4F, 0x8F, 0x08, 0x17, 0x79, 0xF1, 
						   0xE9, 0xF3, 0x94, 0x37, 0x0A, 0xD4, 0x05, 0x89 };
	uint8_t rk[136] = { 0, };
	uint8_t pt[512] = { 0, };
	uint8_t ct[512] = { 0, };
	uint64_t start = 0, end = 0;
    __m512i T[14];

	for (int i = 0; i < 64; i++) {
		pt[i * 8 + 0] = 0xD7;
		pt[i * 8 + 1] = 0x6D;
		pt[i * 8 + 2] = 0x0D;
		pt[i * 8 + 3] = 0x18;
		pt[i * 8 + 4] = 0x32;
		pt[i * 8 + 5] = 0x7E;
		pt[i * 8 + 6] = 0xC5;
		pt[i * 8 + 7] = 0x62;
	}

	AVX512_HIGHT_RoundkeyGen(rk, mk);
	HIGHT_genT(T);

	uint64_t cycle1 = 0;
    for (int i = 0; i < 1000000; i++) {
        start = cpucycles();
        hight_avx512(pt, ct, rk, T);
        end = cpucycles();
        cycle1 += end - start;
    }
    printf("Cycle AVX-512 HIGHT cpb= %lf\n", (float)cycle1 / (1000000 * 64));
}
 

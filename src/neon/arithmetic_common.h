// SPDX-License-Identifier: Apache-2.0

#ifndef ARITHMETIC_COMMON_H
#define ARITHMETIC_COMMON_H

#include <mayo.h>
#include <arithmetic_64.h>
#include <arithmetic_96.h>
#include <arithmetic_128.h>
#include <stdalign.h>
#include <stdint.h>

#include <arm_neon.h>

#define K_OVER_2 ((K_MAX+1)/2)

static const unsigned char __0_f[16] __attribute__((aligned(16))) = {
0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07, 0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};

static const unsigned char __gf16_reduce[16] __attribute__((aligned(16))) = {
0x00,0x13,0x26,0x35,0x4c,0x5f,0x6a,0x79, 0x8b,0x98,0xad,0xbe,0xc7,0xd4,0xe1,0xf2
};

static inline
uint8x16_t _gf16v_mul_unpack_neon( uint8x16_t a0 , uint8x16_t b0 , uint8x16_t tab_reduce )
{
    uint8x16_t ab = vreinterpretq_u8_p8(vmulq_p8( a0 , b0 ));
    return ab^vqtbl1q_u8( tab_reduce , vshrq_n_u8(ab,4) );
}

static inline
uint8x16_t _gf16v_get_multab_neon( uint8x16_t b , uint8x16_t tab_reduce , uint8x16_t tab_0_f ) { return _gf16v_mul_unpack_neon(b,tab_0_f,tab_reduce); }

static inline
uint8x16_t gf16v_get_multab_neon( uint8_t b )
{
    uint8x16_t tab_reduce = vld1q_u8(__gf16_reduce);
    uint8x16_t tab_0_f = vld1q_u8(__0_f);

    uint8x16_t bb = vdupq_n_u8(b);
    return _gf16v_get_multab_neon(bb,tab_reduce,tab_0_f);
}

static inline
uint8x16_t _gf16_tbl_x2( uint8x16_t a , uint8x16_t tbl , uint8x16_t tblhi , uint8x16_t mask_f ) {
    // return vsliq_n_u8( vqtbl1q_u8( tbl , a&mask_f ) , vqtbl1q_u8( tbl , vshrq_n_u8( a , 4 ) ), 4 );
    return vqtbl1q_u8( tbl , a&mask_f ) ^ vqtbl1q_u8( tblhi , vshrq_n_u8( a , 4 ) );
}


#ifndef MAYO_VARIANT
static void m_multiply_bins(const int m_legs, uint64_t *bins, uint64_t *out) {

    m_vec_add(m_legs, bins + 15 * m_legs * 2, bins + 12 * m_legs * 2);
    m_vec_add(m_legs, bins + 15 * m_legs * 2, bins +  3 * m_legs * 2);

    m_vec_add(m_legs, bins + 14 * m_legs * 2, bins +  8 * m_legs * 2);
    m_vec_add(m_legs, bins + 14 * m_legs * 2, bins +  6 * m_legs * 2);

    m_vec_add(m_legs, bins + 13 * m_legs * 2, bins + 10 * m_legs * 2);
    m_vec_add(m_legs, bins + 13 * m_legs * 2, bins +  7 * m_legs * 2);

    m_vec_add(m_legs, bins + 12 * m_legs * 2, bins +  8 * m_legs * 2);
    m_vec_add(m_legs, bins + 12 * m_legs * 2, bins +  4 * m_legs * 2);

    m_vec_add(m_legs, bins + 11 * m_legs * 2, bins +  9 * m_legs * 2);
    m_vec_add(m_legs, bins + 11 * m_legs * 2, bins +  2 * m_legs * 2);

    m_vec_add(m_legs, bins + 10 * m_legs * 2, bins +  8 * m_legs * 2);
    m_vec_add(m_legs, bins + 10 * m_legs * 2, bins +  2 * m_legs * 2);

    m_vec_add(m_legs, bins + 9 * m_legs * 2, bins +  8 * m_legs * 2);
    m_vec_add(m_legs, bins + 9 * m_legs * 2, bins +  1 * m_legs * 2);

    m_vec_add(m_legs, bins + 7 * m_legs * 2, bins +  4 * m_legs * 2);
    m_vec_add(m_legs, bins + 7 * m_legs * 2, bins +  3 * m_legs * 2);

    m_vec_add(m_legs, bins + 6 * m_legs * 2, bins +  4 * m_legs * 2);
    m_vec_add(m_legs, bins + 6 * m_legs * 2, bins +  2 * m_legs * 2);

    m_vec_add(m_legs, bins + 5 * m_legs * 2, bins +  4 * m_legs * 2);
    m_vec_add(m_legs, bins + 5 * m_legs * 2, bins +  1 * m_legs * 2);

    m_vec_add(m_legs, bins + 3 * m_legs * 2, bins +  2 * m_legs * 2);
    m_vec_add(m_legs, bins + 3 * m_legs * 2, bins +  1 * m_legs * 2);

    m_vec_mul_add_x(m_legs, bins + 8 * m_legs * 2, bins + 4 * m_legs * 2);
    m_vec_mul_add_x(m_legs, bins + 4 * m_legs * 2, bins + 2 * m_legs * 2);
    m_vec_mul_add_x(m_legs, bins + 2 * m_legs * 2, bins + 1 * m_legs * 2);

    m_vec_copy(m_legs, bins + 1 * m_legs * 2, out);
}
#endif

static
inline void mayo_O_multabs_neon(const unsigned char *O, uint8x16_t *O_multabs){
    // build multiplication tables
    for (size_t r = 0; r < V_MAX; r++)
    {
        for (size_t c = 0; c < O_MAX; c+=2)
        {
            O_multabs[O_MAX/2*r + c/2] = gf16v_get_multab_neon(O[O_MAX*r + c]) ^ (gf16v_get_multab_neon(O[O_MAX*r + c + 1]) << 4);
        }
    }
}

static
inline void mayo_V_multabs_neon(const unsigned char *V, uint8x16_t *V_multabs){
    // build multiplication tables
    size_t r;
    for (size_t c = 0; c < V_MAX; c++)
    {
        for (r = 0; r+1 < K_MAX; r+= 2)
        {
            V_multabs[K_OVER_2*c +  r/2] = gf16v_get_multab_neon(V[V_MAX*r + c]) ^ (gf16v_get_multab_neon(V[V_MAX*(r+1) + c]) << 4);
        }
#if K_MAX % 2 == 1
        V_multabs[K_OVER_2*c + r/2] = gf16v_get_multab_neon(V[V_MAX*r + c]);
#endif
    }
}


static const unsigned char mayo_gf16_mul[256] __attribute__((aligned(32))) = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07, 0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e, 0x03,0x01,0x07,0x05,0x0b,0x09,0x0f,0x0d,
    0x00,0x03,0x06,0x05,0x0c,0x0f,0x0a,0x09, 0x0b,0x08,0x0d,0x0e,0x07,0x04,0x01,0x02,
    0x00,0x04,0x08,0x0c,0x03,0x07,0x0b,0x0f, 0x06,0x02,0x0e,0x0a,0x05,0x01,0x0d,0x09,
    0x00,0x05,0x0a,0x0f,0x07,0x02,0x0d,0x08, 0x0e,0x0b,0x04,0x01,0x09,0x0c,0x03,0x06,
    0x00,0x06,0x0c,0x0a,0x0b,0x0d,0x07,0x01, 0x05,0x03,0x09,0x0f,0x0e,0x08,0x02,0x04,
    0x00,0x07,0x0e,0x09,0x0f,0x08,0x01,0x06, 0x0d,0x0a,0x03,0x04,0x02,0x05,0x0c,0x0b,
    0x00,0x08,0x03,0x0b,0x06,0x0e,0x05,0x0d, 0x0c,0x04,0x0f,0x07,0x0a,0x02,0x09,0x01,
    0x00,0x09,0x01,0x08,0x02,0x0b,0x03,0x0a, 0x04,0x0d,0x05,0x0c,0x06,0x0f,0x07,0x0e,
    0x00,0x0a,0x07,0x0d,0x0e,0x04,0x09,0x03, 0x0f,0x05,0x08,0x02,0x01,0x0b,0x06,0x0c,
    0x00,0x0b,0x05,0x0e,0x0a,0x01,0x0f,0x04, 0x07,0x0c,0x02,0x09,0x0d,0x06,0x08,0x03,
    0x00,0x0c,0x0b,0x07,0x05,0x09,0x0e,0x02, 0x0a,0x06,0x01,0x0d,0x0f,0x03,0x04,0x08,
    0x00,0x0d,0x09,0x04,0x01,0x0c,0x08,0x05, 0x02,0x0f,0x0b,0x06,0x03,0x0e,0x0a,0x07,
    0x00,0x0e,0x0f,0x01,0x0d,0x03,0x02,0x0c, 0x09,0x07,0x06,0x08,0x04,0x0a,0x0b,0x05,
    0x00,0x0f,0x0d,0x02,0x09,0x06,0x04,0x0b, 0x01,0x0e,0x0c,0x03,0x08,0x07,0x05,0x0a
};

static
inline void mayo_S1_multabs_neon(const unsigned char *S1, uint8x16_t *S1_multabs) {
    size_t r;
    for (size_t c = 0; c < V_MAX; c++)
    {
        for (r = 0; r+1 < K_MAX; r+= 2)
        {
            S1_multabs[K_OVER_2*c +  r/2] = *((uint8x16_t *)(mayo_gf16_mul + 16*S1[V_MAX*r + c]))
                                          ^ (*((uint8x16_t *)(mayo_gf16_mul + 16*S1[V_MAX*(r+1) + c])) << 4);
        }
#if K_MAX % 2 == 1
        S1_multabs[K_OVER_2*c +  r/2] = *((uint8x16_t *)(mayo_gf16_mul + 16*S1[V_MAX*r + c]));
#endif
    }
}

static
inline void mayo_S2_multabs_neon(const unsigned char *S2, uint8x16_t *S2_multabs) {
    // build multiplication tables
    size_t r;
    for (size_t c = 0; c < O_MAX; c++)
    {
        for (r = 0; r+1 < K_MAX; r+= 2)
        {
            S2_multabs[K_OVER_2*c +  r/2] = *((uint8x16_t *)(mayo_gf16_mul + 16*S2[O_MAX*r + c]))
                                          ^ (*((uint8x16_t *)(mayo_gf16_mul + 16*S2[O_MAX*(r+1) + c])) << 4);
        }
#if K_MAX % 2 == 1
        S2_multabs[K_OVER_2*c +  r/2] = *((uint8x16_t *)(mayo_gf16_mul + 16*S2[O_MAX*r + c])) ;
#endif
    }
}

#endif

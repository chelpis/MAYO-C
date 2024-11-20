// SPDX-License-Identifier: Apache-2.0

#ifndef AESCTR_H
#define AESCTR_H

#include <stddef.h>
#include <stdint.h>

void AES_256_ECB(const uint8_t *input, const uint8_t *key, uint8_t *output);
#define AES_ECB_encrypt AES_256_ECB

#ifdef ENABLE_AESNI
int AES_128_CTR_NI(unsigned char *output, size_t outputByteLen,
                   const unsigned char *input, size_t inputByteLen);
int AES_128_CTR_4R_NI(unsigned char *output, size_t outputByteLen,
                      const unsigned char *input, size_t inputByteLen);
#define AES_128_CTR AES_128_CTR_NI
#else
int AES_128_CTR(unsigned char *output, size_t outputByteLen,
                const unsigned char *input, size_t inputByteLen);

typedef struct {
    uint32_t ivw[16];
    uint64_t *sk_exp;

    unsigned char out[64];
    int left;
} aes128ctr_ctx;

void AES_128_CTR_init(aes128ctr_ctx *ctx,  const unsigned char *iv, const unsigned char *input);
void AES_128_CTR_get(aes128ctr_ctx *ctx, unsigned char *out, const int outlen);
void AES_128_CTR_set_position(aes128ctr_ctx *ctx, const unsigned char *iv, const int pos);
void AES_128_CTR_release(aes128ctr_ctx *ctx);

#endif

#endif


#pragma once

#ifdef __cplusplus
extern "C" {
#endif


void aes128_init_x86(aes128_key* context, const uint8_t* key);
void aes128_init_dec_x86(aes128_key* context, const uint8_t* key);
void aes128_ecb_encrypt_x86(const aes128_key* context, const uint8_t* input, uint8_t* output);
void aes128_ecb_decrypt_x86(const aes128_key* context, const uint8_t* input, uint8_t* output);
void aes128_ctr_xor_x86(const aes128_key* context, const uint8_t* iv, uint8_t* buffer, size_t size);
void aes128_cmac_process_x86(const aes128_key* ctx, uint8_t* block, const uint8_t *buffer, uint32_t size);
void aes128_psp_decrypt_x86(const aes128_key* ctx, const uint8_t* prev, const uint8_t* block, uint8_t* buffer, uint32_t size);

void region_xor_sse(   unsigned char* dst, unsigned char* src, int block_size);

#ifdef __cplusplus
}
#endif

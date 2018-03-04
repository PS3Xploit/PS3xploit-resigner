#ifndef _AES_OMAC_H_
#define _AES_OMAC_H_

#include "types.h"

#define AES_OMAC1_DIGEST_SIZE 0x10

void aes_omac1(u8 *digest, u8 *input, u32 length, u8 *key, u32 keybits);

#endif

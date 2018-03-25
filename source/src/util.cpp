/*
* Copyright (c) 2011-2013 by naehrwert
* This file is released under the GPLv2.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "types.h"
#include "util.h"

u8 *_read_buffer(const s8 *file, u32 *length)
{
	FILE *fp;
	u32 size;

	if((fp = fopen(file, "rb")) == NULL)
		return NULL;

	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	u8 *buffer = (u8 *)malloc(sizeof(u8) * size);
	fread(buffer, sizeof(u8), size, fp);

	if(length != NULL)
		*length = size;

	fclose(fp);

	return buffer;
}

int _write_buffer(const s8 *file, u8 *buffer, u32 length)
{
	FILE *fp;

	if((fp = fopen(file, "wb")) == NULL)
		return 0;

	/**/
	while(length > 0)
	{
		u32 wrlen = 1024;
		if(length < 1024)
			wrlen = length;
		fwrite(buffer, sizeof(u8), wrlen, fp);
		length -= wrlen;
		buffer += 1024;
	}
	/**/

	//fwrite(buffer, sizeof(u8), length, fp);

	fclose(fp);

	return 1;
}

#include "aes.h"
// Crypto functions (AES128-CBC, AES128-ECB, SHA1-HMAC and AES-CMAC).
void aescbc128_decrypt(unsigned char *key, unsigned char *iv, unsigned char *in, unsigned char *out, int len)
{
	aes_context ctx;
	aes_setkey_dec(&ctx, key, 128);
	aes_crypt_cbc(&ctx, AES_DECRYPT, len, iv, in, out);

	// Reset the IV.
	memset(iv, 0, 0x10);
}

void aescbc128_encrypt(unsigned char *key, unsigned char *iv, unsigned char *in, unsigned char *out, int len)
{
	aes_context ctx;
	aes_setkey_enc(&ctx, key, 128);
	aes_crypt_cbc(&ctx, AES_ENCRYPT, len, iv, in, out);

	// Reset the IV.
	memset(iv, 0, 0x10);
}

void aesecb128_encrypt(unsigned char *key, unsigned char *in, unsigned char *out)
{
	aes_context ctx;
	aes_setkey_enc(&ctx, key, 128);
	aes_crypt_ecb(&ctx, AES_ENCRYPT, in, out);
}

int aes128ctr(u8 *key, u8 *iv, u8 *in, u64 len, u8 *out)
{
	aes_context aes_ctx = {0};		
	size_t nc_off = 0;	
	unsigned char stream_block[0x10] = {0};
	int retval = -1;


	// validate input params
	if ( (key == NULL) || (iv == NULL) || (in == NULL) || (out == NULL) )
		goto exit;		
	
	// set the AES key context
	if (aes_setkey_enc(&aes_ctx, key, 128) != 0)
		goto exit;	

	// do the AES-CTR crypt
	if (aes_crypt_ctr(&aes_ctx, (size_t)len, &nc_off, iv, stream_block, in, out) != 0)
			goto exit;	
	// status success
	retval = 0;
	
exit:
	// return status
	return retval;
}

int aes128ctrxor(u8 *key, u8 *iv, u8 *in, u64 len, u8 *out, size_t len_start_from)
{
	aes_context aes_ctx = {0};		
	size_t nc_off = 0;	
	unsigned char stream_block[0x10] = {0};
	int retval = -1;


	// validate input params
	if ( (key == NULL) || (iv == NULL) || (in == NULL) || (out == NULL) )
		goto exit;		
	
	// set the AES key context
	if (aes_setkey_enc(&aes_ctx, key, 128) != 0)
		goto exit;	

	// do the AES-CTR crypt
	if (aes_crypt_ctr_xor(&aes_ctx, (size_t)len, &nc_off, iv, stream_block, in, out, len_start_from) != 0)
			goto exit;	
	// status success
	retval = 0;
	
exit:
	// return status
	return retval;
}

unsigned char RAP_KEY[] = {0x86, 0x9F, 0x77, 0x45, 0xC1, 0x3F, 0xD8, 0x90, 0xCC, 0xF2, 0x91, 0x88, 0xE3, 0xCC, 0x3E, 0xDF};
unsigned char RAP_PBOX[] = {0x0C, 0x03, 0x06, 0x04, 0x01, 0x0B, 0x0F, 0x08, 0x02, 0x07, 0x00, 0x05, 0x0A, 0x0E, 0x0D, 0x09};
unsigned char RAP_E1[] = {0xA9, 0x3E, 0x1F, 0xD6, 0x7C, 0x55, 0xA3, 0x29, 0xB7, 0x5F, 0xDD, 0xA6, 0x2A, 0x95, 0xC7, 0xA5};
unsigned char RAP_E2[] = {0x67, 0xD4, 0x5D, 0xA3, 0x29, 0x6D, 0x00, 0x6A, 0x4E, 0x7C, 0x53, 0x7B, 0xF5, 0x53, 0x8C, 0x74};

void get_rif_key(unsigned char* rap, unsigned char* rif)
{
	int i;
	int round;

	unsigned char key[0x10];
	unsigned char iv[0x10];
	memset(key, 0, 0x10);
	memset(iv, 0, 0x10);

	// Initial decrypt.
	aescbc128_decrypt(RAP_KEY, iv, rap, key, 0x10);

	// rap2rifkey round.
	for (round = 0; round < 5; ++round)
	{
		for (i = 0; i < 16; ++i)
		{
			int p = RAP_PBOX[i];
			key[p] ^= RAP_E1[p];
		}
		for (i = 15; i >= 1; --i)
		{
			int p = RAP_PBOX[i];
			int pp = RAP_PBOX[i - 1];
			key[p] ^= key[pp];
		}
		int o = 0;
		for (i = 0; i < 16; ++i)
		{
			int p = RAP_PBOX[i];
			unsigned char kc = key[p] - o;
			unsigned char ec2 = RAP_E2[p];
			if (o != 1 || kc != 0xFF)
			{
				o = kc < ec2 ? 1 : 0;
				key[p] = kc - ec2;
			}
			else if (kc == 0xFF)
			{
				key[p] = kc - ec2;
			}
			else
			{
				key[p] = kc;
			}
		}
	}

	memcpy(rif, key, 0x10);
}

bool hmac_hash_compare(unsigned char *key, int key_len, unsigned char *in, int in_len, unsigned char *hash, int hash_len)

{

	unsigned char *out = new unsigned char[key_len];



	sha1_hmac(key, key_len, in, in_len, out);



	for (int i = 0; i < hash_len; i++)

	{

		if (out[i] != hash[i])

		{

			delete[] out;

			return false;

		}

	}



	delete[] out;



	return true;

}


// Auxiliary functions (endian swap, xor and prng).

short se16(short i)

{

	return (((i & 0xFF00) >> 8) | ((i & 0xFF) << 8));

}



int se32(int i)

{

	return ((i & 0xFF000000) >> 24) | ((i & 0xFF0000) >>  8) | ((i & 0xFF00) <<  8) | ((i & 0xFF) << 24);

}



u64 se64(u64 i)

{

	return ((i & 0x00000000000000ff) << 56) | ((i & 0x000000000000ff00) << 40) |

		((i & 0x0000000000ff0000) << 24) | ((i & 0x00000000ff000000) <<  8) |

		((i & 0x000000ff00000000) >>  8) | ((i & 0x0000ff0000000000) >> 24) |

		((i & 0x00ff000000000000) >> 40) | ((i & 0xff00000000000000) >> 56);

}



void xor1(unsigned char *dest, unsigned char *src1, unsigned char *src2, int size)

{

	int i;

	for(i = 0; i < size; i++)

	{

		dest[i] = src1[i] ^ src2[i];

	}

}



void prng(unsigned char *dest, int size)

{

    unsigned char *buffer = new unsigned char[size];

	srand((u32)time(0));



	int i;

	for(i = 0; i < size; i++)

      buffer[i] = (unsigned char)(rand() & 0xFF);



	memcpy(dest, buffer, size);



	delete[] buffer;

}



// Hex string conversion auxiliary functions.

u64 hex_to_u64(const char* hex_str)

{

	u32 length = strlen(hex_str);

	u64 tmp = 0;

	u64 result = 0;

	char c;



	while (length--)

	{

		c = *hex_str++;

		if((c >= '0') && (c <= '9'))

			tmp = c - '0';

		else if((c >= 'a') && (c <= 'f'))

			tmp = c - 'a' + 10;

		else if((c >= 'A') && (c <= 'F'))

			tmp = c - 'A' + 10;

		else

			tmp = 0;

		result |= (tmp << (length * 4));

	}



	return result;

}



void hex_to_bytes(unsigned char *data, const char *hex_str, unsigned int str_length)

{

	u32 data_length = str_length / 2;

	char tmp_buf[3] = {0, 0, 0};



	// Don't convert if the string length is odd.

	if (!(str_length % 2))

	{

		u8 *out = (u8 *) malloc (str_length * sizeof(u8));

		u8 *pos = out;



		while (str_length--)

		{

			tmp_buf[0] = *hex_str++;

			tmp_buf[1] = *hex_str++;



			*pos++ = (u8)(hex_to_u64(tmp_buf) & 0xFF);

		}



		// Copy back to our array.

		memcpy(data, out, data_length);

	}

}



bool is_hex(const char* hex_str, unsigned int str_length)

{

    static const char hex_chars[] = "0123456789abcdefABCDEF";



    if (hex_str == NULL)

        return false;



    unsigned int i;

    for (i = 0; i < str_length; i++)

	{

		if (strchr(hex_chars, hex_str[i]) == 0)

			return false;

	}



    return true;

}



void hmac_hash_forge(unsigned char *key, int key_len, unsigned char *in, int in_len, unsigned char *hash)

{

	sha1_hmac(key, key_len, in, in_len, hash);

}



bool cmac_hash_compare(unsigned char *key, int key_len, unsigned char *in, int in_len, unsigned char *hash, int hash_len)

{

	unsigned char *out = new unsigned char[key_len];



	aes_context ctx;

	aes_setkey_enc(&ctx, key, 128);

	aes_cmac(&ctx, in_len, in, out);



	for (int i = 0; i < hash_len; i++)

	{

		if (out[i] != hash[i])

		{

			delete[] out;

			return false;

		}

	}



	delete[] out;



	return true;

}



void cmac_hash_forge(unsigned char *key, int key_len, unsigned char *in, uint64_t in_len, unsigned char *hash)

{

	aes_context ctx;

	aes_setkey_enc(&ctx, key, 128);

	aes_cmac(&ctx, in_len, in, hash);

}

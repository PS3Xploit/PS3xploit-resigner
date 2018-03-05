/*
* Copyright (c) 2011-2013 by naehrwert
* This file is released under the GPLv2.
*/

#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdio.h>

#include "types.h"
#include "sha1.h"
#include <stdint.h>

/*! Verbose. */
extern BOOL _verbose;
#define _LOG_VERBOSE(...) _IF_VERBOSE(printf("[*] " __VA_ARGS__))
#define _IF_VERBOSE(code) \
	do \
	{ \
		if(_verbose == TRUE) \
		{ \
			code; \
		} \
	} while(0)

/*! Raw. */
extern BOOL _raw;
#define _PRINT_RAW(fp, ...) _IF_RAW(fprintf(fp, __VA_ARGS__))
#define _IF_RAW(code) \
	do \
	{ \
		if(_raw == TRUE) \
		{ \
			code; \
		} \
	} while(0)

/*! ID to name entry. */
typedef struct _id_to_name
{
	u64 id;
	const s8 *name;
} id_to_name_t;

/*! Utility functions. */
u8 *_read_buffer(const s8 *file, u32 *length);
int _write_buffer(const s8 *file, u8 *buffer, u32 length);
// Crypto functions (AES128-CBC, AES128-ECB, SHA1-HMAC and AES-CMAC).
void aescbc128_decrypt(unsigned char *key, unsigned char *iv, unsigned char *in, unsigned char *out, int len);
void aescbc128_encrypt(unsigned char *key, unsigned char *iv, unsigned char *in, unsigned char *out, int len);
void aesecb128_encrypt(unsigned char *key, unsigned char *in, unsigned char *out);
void get_rif_key(unsigned char* rap, unsigned char* rif);
int aes128ctr(u8 *key, u8 *iv, u8 *in, u64 len, u8 *out);
int aes128ctrxor(u8 *key, u8 *iv, u8 *in, u64 len, u8 *out,size_t len_start_from);

bool hmac_hash_compare(unsigned char *key, int key_len, unsigned char *in, int in_len, unsigned char *hash, int hash_len);

void hmac_hash_forge(unsigned char *key, int key_len, unsigned char *in, int in_len, unsigned char *hash);

bool cmac_hash_compare(unsigned char *key, int key_len, unsigned char *in, int in_len, unsigned char *hash, int hash_len);

void cmac_hash_forge(unsigned char *key, int key_len, unsigned char *in, uint64_t in_len, unsigned char *hash);

short se16(short i);

int se32(int i);

u64 se64(u64 i);

void xor1(unsigned char *dest, unsigned char *src1, unsigned char *src2, int size);

void prng(unsigned char *dest, int size);


// Hex string conversion auxiliary functions.

u64 hex_to_u64(const char* hex_str);

void hex_to_bytes(unsigned char *data, const char *hex_str, unsigned int str_length);

bool is_hex(const char* hex_str, unsigned int str_length);

#endif

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include <sys/types.h>
#include <sys/stat.h>

#define IDPS_KEYBITS 128
#define ACT_DAT_KEYBITS 128
#define RIF_KEYBITS 128
#define RAP_KEYBITS 128
#include "aes.h"
#include "util.h"
#include "sha1.h"
#include "pkg2zip_aes.h"

#ifdef _WIN32
#define fseek _fseeki64
#define ftell _ftelli64
#endif

uint8_t p_fixed[20]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x01,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
uint8_t a_fixed[20]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x01,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFC};
uint8_t b_fixed[20]={0xA6,0x8B,0xED,0xC3,0x34,0x18,0x02,0x9C,0x1D,0x3C,0xE3,0x3B,0x9A,0x32,0x1F,0xCC,0xBB,0x9E,0x0F,0x0B};
uint8_t n_fixed[21]={0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xB5,0xAE,0x3C,0x52,0x3E,0x63,0x94,0x4F,0x21,0x27};
uint8_t gx_fixed[20]={0x12,0x8E,0xC4,0x25,0x64,0x87,0xFD,0x8F,0xDF,0x64,0xE2,0x43,0x7B,0xC0,0xA1,0xF6,0xD5,0xAF,0xDE,0x2C};
uint8_t gy_fixed[20]={0x59,0x58,0x55,0x7E,0xB1,0xDB,0x00,0x12,0x60,0x42,0x55,0x24,0xDB,0xC3,0x79,0xD5,0xAC,0x5F,0x4A,0xDF};

uint8_t ec_p_nm[20]={0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x4A, 0x51, 0xC3, 0xAD, 0xC1, 0x9C, 0x6B, 0xB0, 0xDE, 0xD8};
uint8_t ec_a_nm[20]={0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF ,0xFF ,0xFF, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
uint8_t ec_b_nm[20]={0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03};
uint8_t ec_G_nm[40]={0xED, 0x71, 0x3B, 0xDA, 0x9B, 0x78, 0x02, 0x70, 0x20, 0x9B, 0x1D, 0xBC, 0x84, 0x3F, 0x5E, 0x09, 0x2A, 0x50, 0x21, 0xD3, 0xA6, 0xA7, 0xAA, 0x81, 0x4E, 0x24, 0xFF, 0xED, 0x9F, 0xBD, 0xAA, 0xDB, 0x24, 0x3C, 0x86, 0x2A, 0x53, 0xA0, 0xB5, 0x20};
uint8_t ec_N_nm[20]={0x59, 0x74, 0x12, 0x3C, 0xCB, 0xE7, 0xFD, 0x63, 0xE2, 0xC3, 0x1C, 0xC4, 0x65, 0xCD, 0xE0, 0x33, 0x44, 0x61 ,0xF0, 0xF4};

//uint8_t ec_k[21]={0x00,0x42,0x75,0x72,0x6E,0x20,0x49,0x6E,0x20,0x48,0x65,0x6C,0x6C,0x20,0x53,0x6F,0x6E,0x79,0x20,0x21,0x21};
//uint8_t ec_Q_nm[40]={0x7C,0xFD,0x88,0x8E,0xE9,0xDD,0x5F,0x60,0x30,0xA5,0xC1,0xC0,0xA2,0xF9,0x08,0x4A,0x74,0xB1,0x32,0x87,0x33,0x52,0x68,0x11,0xCF,0xBA,0x95,0x35,0x06,0xE4,0x41,0x11,0xF0,0xE2,0xD6,0xF2,0xD1,0x91,0x3E,0x69};

uint8_t ec_k[21]={0x00,0xbf,0x21,0x22,0x4b,0x04,0x1f,0x29,0x54,0x9d,0xb2,0x5e,0x9a,0xad,0xe1,0x9e,0x72,0x0a,0x1f,0xe0,0xf1};
uint8_t ec_Q_nm[40]={0x94,0x8D,0xA1,0x3E,0x8C,0xAF,0xD5,0xBA,0x0E,0x90,0xCE,0x43,0x44,0x61,0xBB,0x32,0x7F,0xE7,0xE0,0x80,0x47,0x5E,0xAA,0x0A,0xD3,0xAD,0x4F,0x5B,0x62,0x47,0xA7,0xFD,0xA8,0x6D,0xF6,0x97,0x90,0x19,0x67,0x73};

struct point {
	u8 x[20];
	u8 y[20];
};


static uint8_t ec_p[20];
static uint8_t ec_a[20];
static uint8_t ec_b[20];
static point ec_G;
static point ec_Q;
static uint8_t ec_N[21];

#define MT_N 624
#define MT_M 397
#define MT_MATRIX_A 0x9908b0df
#define MT_UPPER_MASK 0x80000000
#define MT_LOWER_MASK 0x7fffffff

/*! Mersenne-Twister 19937 context. */
typedef struct _mt19937_ctxt
{
	/*! State. */
	unsigned int state[MT_N];
	/*! Index. */
	unsigned int idx;
} mt19937_ctxt_t;

void mt19937_init(mt19937_ctxt_t *ctxt, unsigned int seed)
{
	ctxt->state[0] = seed;

	for(ctxt->idx = 1; ctxt->idx < MT_N; ctxt->idx++)
		ctxt->state[ctxt->idx] = (1812433253 * (ctxt->state[ctxt->idx - 1] ^ (ctxt->state[ctxt->idx - 1] >> 30)) + ctxt->idx);

	ctxt->idx = MT_M + 1;
}

unsigned int mt19937_update(mt19937_ctxt_t *ctxt)
{
	unsigned int y, k;
	static unsigned int mag01[2] = {0, MT_MATRIX_A};

	if(ctxt->idx >= MT_N)
	{
		for(k = 0; k < MT_N - MT_M; k++)
		{
			y = (ctxt->state[k] & MT_UPPER_MASK) |
				(ctxt->state[k + 1] & MT_LOWER_MASK);
			ctxt->state[k] = ctxt->state[k + MT_M] ^ (y >> 1) ^ mag01[y & 1];
		}

		for(; k < MT_N - 1; k++)
		{
			y = (ctxt->state[k] & MT_UPPER_MASK) |
				(ctxt->state[k + 1] & MT_LOWER_MASK);
			ctxt->state[k] = ctxt->state[k + (MT_M - MT_N)] ^ (y >> 1) ^ mag01[y & 1];
		}

		y = (ctxt->state[MT_N - 1] & MT_UPPER_MASK) |
			(ctxt->state[0] & MT_LOWER_MASK);
		ctxt->state[MT_N - 1] = ctxt->state[MT_M - 1] ^ (y >> 1) ^ mag01[y & 1];

		ctxt->idx = 0;
	}

	y = ctxt->state[ctxt->idx++];

	y ^= (y >> 11);
	y ^= (y << 7) & 0x9d2c5680UL;
	y ^= (y << 15) & 0xefc60000UL;
	y ^= (y >> 18);

	return y;
}

static mt19937_ctxt_t _mt19937_ctxt;
static BOOL _mt_init = FALSE;

u8 _get_rand_byte()
{
	if(_mt_init == FALSE)
	{
		_mt_init = TRUE;
		mt19937_init(&_mt19937_ctxt, clock());
	}

	return (u8)(mt19937_update(&_mt19937_ctxt) & 0xFF);
}

void _fill_rand_bytes(u8 *dst, u32 len)
{
	u32 i;

	for(i = 0; i < len; i++)
		dst[i] = _get_rand_byte();
}

static void memcpy_inv(u8 *dst, u8 *src, u32 len)
{
	u32 j;

	for (j = 0; j < len; j++)
		dst[j] = ~src[j];
}

void bn_print(char *name, u8 *a, u32 n)
{
	u32 i;

	printf("%s = ", name);

	for (i = 0; i < n; i++)
		printf("%02x", a[i]);

	printf("\n");
}

static void bn_zero(u8 *d, u32 n)
{
	memset(d, 0, n);
}

void bn_copy(u8 *d, u8 *a, u32 n)
{
	memcpy(d, a, n);
}

int bn_compare(u8 *a, u8 *b, u32 n)
{
	u32 i;

	for (i = 0; i < n; i++) {
		if (a[i] < b[i])
			return -1;
		if (a[i] > b[i])
			return 1;
	}

	return 0;
}

static u8 bn_add_1(u8 *d, u8 *a, u8 *b, u32 n)
{
	u32 i;
	u32 dig;
	u8 c;

	c = 0;
	for (i = n - 1; i < n; i--) {
		dig = a[i] + b[i] + c;
		c = dig >> 8;
		d[i] = dig;
	}

	return c;
}

static u8 bn_sub_1(u8 *d, u8 *a, u8 *b, u32 n)
{
	u32 i;
	u32 dig;
	u8 c;

	c = 1;
	for (i = n - 1; i < n; i--) {
		dig = a[i] + 255 - b[i] + c;
		c = dig >> 8;
		d[i] = dig;
	}

	return 1 - c;
}

void bn_reduce(u8 *d, u8 *N, u32 n)
{
	if (bn_compare(d, N, n) >= 0)
		bn_sub_1(d, d, N, n);
}

void bn_add(u8 *d, u8 *a, u8 *b, u8 *N, u32 n)
{
	if (bn_add_1(d, a, b, n))
		bn_sub_1(d, d, N, n);

	bn_reduce(d, N, n);
}

void bn_sub(u8 *d, u8 *a, u8 *b, u8 *N, u32 n)
{
	if (bn_sub_1(d, a, b, n))
		bn_add_1(d, d, N, n);
}

static const u8 inv256[0x80] = {
	0x01, 0xab, 0xcd, 0xb7, 0x39, 0xa3, 0xc5, 0xef,
	0xf1, 0x1b, 0x3d, 0xa7, 0x29, 0x13, 0x35, 0xdf,
	0xe1, 0x8b, 0xad, 0x97, 0x19, 0x83, 0xa5, 0xcf,
	0xd1, 0xfb, 0x1d, 0x87, 0x09, 0xf3, 0x15, 0xbf,
	0xc1, 0x6b, 0x8d, 0x77, 0xf9, 0x63, 0x85, 0xaf,
	0xb1, 0xdb, 0xfd, 0x67, 0xe9, 0xd3, 0xf5, 0x9f,
	0xa1, 0x4b, 0x6d, 0x57, 0xd9, 0x43, 0x65, 0x8f,
	0x91, 0xbb, 0xdd, 0x47, 0xc9, 0xb3, 0xd5, 0x7f,
	0x81, 0x2b, 0x4d, 0x37, 0xb9, 0x23, 0x45, 0x6f,
	0x71, 0x9b, 0xbd, 0x27, 0xa9, 0x93, 0xb5, 0x5f,
	0x61, 0x0b, 0x2d, 0x17, 0x99, 0x03, 0x25, 0x4f,
	0x51, 0x7b, 0x9d, 0x07, 0x89, 0x73, 0x95, 0x3f,
	0x41, 0xeb, 0x0d, 0xf7, 0x79, 0xe3, 0x05, 0x2f,
	0x31, 0x5b, 0x7d, 0xe7, 0x69, 0x53, 0x75, 0x1f,
	0x21, 0xcb, 0xed, 0xd7, 0x59, 0xc3, 0xe5, 0x0f,
	0x11, 0x3b, 0x5d, 0xc7, 0x49, 0x33, 0x55, 0xff,
};

static void bn_mon_muladd_dig(u8 *d, u8 *a, u8 b, u8 *N, u32 n)
{
	u32 dig;
	u32 i;

	u8 z = -(d[n-1] + a[n-1]*b) * inv256[N[n-1]/2];

	dig = d[n-1] + a[n-1]*b + N[n-1]*z;
	dig >>= 8;

	for (i = n - 2; i < n; i--) {
		dig += d[i] + a[i]*b + N[i]*z;
		d[i+1] = dig;
		dig >>= 8;
	}

	d[0] = dig;
	dig >>= 8;

	if (dig)
		bn_sub_1(d, d, N, n);

	bn_reduce(d, N, n);
}

void bn_mon_mul(u8 *d, u8 *a, u8 *b, u8 *N, u32 n)
{
	u8 t[512];
	u32 i;

	bn_zero(t, n);

	for (i = n - 1; i < n; i--)
		bn_mon_muladd_dig(t, a, b[i], N, n);

	bn_copy(d, t, n);
}

void bn_to_mon(u8 *d, u8 *N, u32 n)
{
	u32 i;

	for (i = 0; i < 8*n; i++)
		bn_add(d, d, d, N, n);
}

void bn_from_mon(u8 *d, u8 *N, u32 n)
{
	u8 t[512];

	bn_zero(t, n);
	t[n-1] = 1;
	bn_mon_mul(d, d, t, N, n);
}

static void bn_mon_exp(u8 *d, u8 *a, u8 *N, u32 n, u8 *e, u32 en)
{
	u8 t[512];
	u32 i;
	u8 mask;

	bn_zero(d, n);
	d[n-1] = 1;
	bn_to_mon(d, N, n);

	for (i = 0; i < en; i++)
		for (mask = 0x80; mask != 0; mask >>= 1) {
			bn_mon_mul(t, d, d, N, n);
			if ((e[i] & mask) != 0)
				bn_mon_mul(d, t, a, N, n);
			else
				bn_copy(d, t, n);
		}
}

static void elt_copy(u8 *d, u8 *a)
{
	memcpy(d, a, 20);
}

static void elt_zero(u8 *d)
{
	memset(d, 0, 20);
}

static int elt_is_zero(u8 *d)
{
	u32 i;

	for (i = 0; i < 20; i++)
		if (d[i] != 0)
			return 0;

	return 1;
}

static void elt_add(u8 *d, u8 *a, u8 *b)
{
	bn_add(d, a, b, ec_p, 20);
}

static void elt_sub(u8 *d, u8 *a, u8 *b)
{
	bn_sub(d, a, b, ec_p, 20);
}

static void elt_mul(u8 *d, u8 *a, u8 *b)
{
	bn_mon_mul(d, a, b, ec_p, 20);
}

static void elt_square(u8 *d, u8 *a)
{
	elt_mul(d, a, a);
}

void bn_mon_inv(u8 *d, u8 *a, u8 *N, u32 n)
{
	u8 t[512], s[512];

	bn_zero(s, n);
	s[n-1] = 2;
	bn_sub_1(t, N, s, n);
	bn_mon_exp(d, a, N, n, t, n);
}

static void elt_inv(u8 *d, u8 *a)
{
	u8 s[20];
	elt_copy(s, a);
	bn_mon_inv(d, s, ec_p, 20);
}

static void point_to_mon(struct point *p)
{
	bn_to_mon(p->x, ec_p, 20);
	bn_to_mon(p->y, ec_p, 20);
}

static void point_from_mon(struct point *p)
{
	bn_from_mon(p->x, ec_p, 20);
	bn_from_mon(p->y, ec_p, 20);
}

static void point_zero(struct point *p)
{
	elt_zero(p->x);
	elt_zero(p->y);
}

static int point_is_zero(struct point *p)
{
	return elt_is_zero(p->x) && elt_is_zero(p->y);
}

static void point_double(struct point *r, struct point *p)
{
	u8 s[20], t[20];
	struct point pp;
	u8 *px, *py, *rx, *ry;

	pp = *p;

	px = pp.x;
	py = pp.y;
	rx = r->x;
	ry = r->y;

	if (elt_is_zero(py)) {
		point_zero(r);
		return;
	}

	elt_square(t, px);	// t = px*px
	elt_add(s, t, t);	// s = 2*px*px
	elt_add(s, s, t);	// s = 3*px*px
	elt_add(s, s, ec_a);	// s = 3*px*px + a
	elt_add(t, py, py);	// t = 2*py
	elt_inv(t, t);		// t = 1/(2*py)
	elt_mul(s, s, t);	// s = (3*px*px+a)/(2*py)

	elt_square(rx, s);	// rx = s*s
	elt_add(t, px, px);	// t = 2*px
	elt_sub(rx, rx, t);	// rx = s*s - 2*px

	elt_sub(t, px, rx);	// t = -(rx-px)
	elt_mul(ry, s, t);	// ry = -s*(rx-px)
	elt_sub(ry, ry, py);	// ry = -s*(rx-px) - py
}

static void point_add(struct point *r, struct point *p, struct point *q)
{
	u8 s[20], t[20], u[20];
	u8 *px, *py, *qx, *qy, *rx, *ry;
	struct point pp, qq;

	pp = *p;
	qq = *q;

	px = pp.x;
	py = pp.y;
	qx = qq.x;
	qy = qq.y;
	rx = r->x;
	ry = r->y;

	if (point_is_zero(&pp)) {
		elt_copy(rx, qx);
		elt_copy(ry, qy);
		return;
	}

	if (point_is_zero(&qq)) {
		elt_copy(rx, px);
		elt_copy(ry, py);
		return;
	}

	elt_sub(u, qx, px);

	if (elt_is_zero(u)) {
		elt_sub(u, qy, py);
		if (elt_is_zero(u))
			point_double(r, &pp);
		else
			point_zero(r);

		return;
	}

	elt_inv(t, u);		// t = 1/(qx-px)
	elt_sub(u, qy, py);	// u = qy-py
	elt_mul(s, t, u);	// s = (qy-py)/(qx-px)

	elt_square(rx, s);	// rx = s*s
	elt_add(t, px, qx);	// t = px+qx
	elt_sub(rx, rx, t);	// rx = s*s - (px+qx)

	elt_sub(t, px, rx);	// t = -(rx-px)
	elt_mul(ry, s, t);	// ry = -s*(rx-px)
	elt_sub(ry, ry, py);	// ry = -s*(rx-px) - py
}

static void point_mul(struct point *d, u8 *a, struct point *b)	// a is bignum
{
	u32 i;
	u8 mask;

	point_zero(d);

	for (i = 0; i < 21; i++)
		for (mask = 0x80; mask != 0; mask >>= 1) {
			point_double(d, d);
			if ((a[i] & mask) != 0)
				point_add(d, d, b);
		}
}

static void generate_ecdsa(u8 *R, u8 *S, u8 *k, u8 *hash)
{
	u8 e[21];
	u8 kk[21];
	u8 m[21];
	u8 minv[21];
	struct point mG;

	e[0] = 0;
	memcpy(e + 1, hash, 20);
	bn_reduce(e, ec_N, 21);

try_again:
	_fill_rand_bytes(m, 21);
	m[0] = 0;
	if (bn_compare(m, ec_N, 21) >= 0)
		goto try_again;

	//	R = (mG).x
	point_mul(&mG, m, &ec_G);
	point_from_mon(&mG);
	R[0] = 0;
	elt_copy(R+1, mG.x);

	//	S = m**-1*(e + Rk) (mod N)

	bn_copy(kk, k, 21);
	bn_reduce(kk, ec_N, 21);
	bn_to_mon(m, ec_N, 21);
	bn_to_mon(e, ec_N, 21);
	bn_to_mon(R, ec_N, 21);
	bn_to_mon(kk, ec_N, 21);

	bn_mon_mul(S, R, kk, ec_N, 21);
	bn_add(kk, S, e, ec_N, 21);
	bn_mon_inv(minv, m, ec_N, 21);
	bn_mon_mul(S, minv, kk, ec_N, 21);

	bn_from_mon(R, ec_N, 21);
	bn_from_mon(S, ec_N, 21);
}

int set_vsh_curve(u8 *p, u8 *a, u8 *b, u8 *N, u8 *Gx, u8 *Gy)
{	
	memcpy(p,p_fixed, 20);
	memcpy(a, a_fixed, 20);
	memcpy(b, b_fixed, 20);
	memcpy(N, n_fixed, 21);
	memcpy(Gx, gx_fixed, 20);
	memcpy(Gy, gy_fixed, 20);

	return 0;
}

int ecdsa_set_curve()
{
	set_vsh_curve(ec_p, ec_a, ec_b, ec_N, ec_G.x, ec_G.y);
	bn_to_mon(ec_a, ec_p, 20);
	bn_to_mon(ec_b, ec_p, 20);

	point_to_mon(&ec_G);
	return 0;
}

void ecdsa_set_pub()
{
	memcpy(ec_Q.x, ec_Q_nm,20);
	memcpy(ec_Q.y, ec_Q_nm+20,20);
	point_to_mon(&ec_Q);
}

void ecdsa_set_priv()
{
	//ec_k already set
}

static int check_ecdsa(struct point *Q, u8 *R, u8 *S, u8 *hash)
{
	u8 Sinv[21];
	u8 e[21];
	u8 w1[21], w2[21];
	struct point r1, r2;
	u8 rr[21];

	e[0] = 0;
	memcpy(e + 1, hash, 20);
	bn_reduce(e, ec_N, 21);

	bn_to_mon(R, ec_N, 21);
	bn_to_mon(S, ec_N, 21);
	bn_to_mon(e, ec_N, 21);

	bn_mon_inv(Sinv, S, ec_N, 21);

	bn_mon_mul(w1, e, Sinv, ec_N, 21);
	bn_mon_mul(w2, R, Sinv, ec_N, 21);

	bn_from_mon(w1, ec_N, 21);
	bn_from_mon(w2, ec_N, 21);

	point_mul(&r1, w1, &ec_G);
	point_mul(&r2, w2, Q);

	point_add(&r1, &r1, &r2);

	point_from_mon(&r1);

	rr[0] = 0;
	memcpy(rr + 1, r1.x, 20);
	bn_reduce(rr, ec_N, 21);

	bn_from_mon(R, ec_N, 21);
	bn_from_mon(S, ec_N, 21);

	return (bn_compare(rr, R, 21) == 0);
}

void ecdsa_sign(u8 *hash, u8 *R, u8 *S)
{
	generate_ecdsa(R, S, ec_k, hash);
}

//! Byte swap unsigned short
uint16_t swap_uint16( uint16_t val ) 
{
    return (val << 8) | (val >> 8 );
}

//! Byte swap short
int16_t swap_int16( int16_t val ) 
{
    return (val << 8) | ((val >> 8) & 0xFF);
}

//! Byte swap unsigned int
uint32_t swap_uint32( uint32_t val )
{
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF ); 
    return (val << 16) | (val >> 16);
}

//! Byte swap int
int32_t swap_int32( int32_t val )
{
    val = ((val << 8) & 0xFF00FF00) | ((val >> 8) & 0xFF00FF ); 
    return (val << 16) | ((val >> 16) & 0xFFFF);
}

int64_t swap_int64( int64_t val )
{
    val = ((val << 8) & 0xFF00FF00FF00FF00ULL ) | ((val >> 8) & 0x00FF00FF00FF00FFULL );
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL ) | ((val >> 16) & 0x0000FFFF0000FFFFULL );
    return (val << 32) | ((val >> 32) & 0xFFFFFFFFULL);
}

uint64_t swap_uint64( uint64_t val )
{
    val = ((val << 8) & 0xFF00FF00FF00FF00ULL ) | ((val >> 8) & 0x00FF00FF00FF00FFULL );
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL ) | ((val >> 16) & 0x0000FFFF0000FFFFULL );
    return (val << 32) | (val >> 32);
}

FILE *forge_act_dat()
{
	uint64_t timestamp=0x1619BF6DDCA; //today
	uint32_t version=1;
	version=swap_uint32(version);
	uint32_t unk=2;
	unk=swap_uint32(unk);
	uint64_t psn_id=2;
	psn_id=swap_uint64(psn_id);
	timestamp=swap_uint64(timestamp);
	FILE *fp=fopen("act.dat","wb");
	uint8_t *act_dat=new uint8_t[0x1038];
	memset(act_dat,0x11, 0x1038);
	memcpy(act_dat, &version, 4);
	memcpy(act_dat+4, &unk,4);
	memcpy(act_dat+8, &psn_id, 8);
	memcpy(act_dat+0x870, &timestamp, 8);
	fwrite(act_dat, 0x1038,1,fp);
	fclose(fp);
	return fp=fopen("act.dat", "rb");
}

int read_act_dat_and_make_rif(char *path)
{
	char *content_id=(char *)malloc(256);
	memset(content_id,0,256);
	strcpy(content_id, path);
	char *slash2 = strrchr (content_id, '\\');
	if (slash2 != NULL)
	{
		*slash2 = '\0';
		content_id=slash2+1;
	}
	
	char *slash_rev = strrchr (content_id, '/');
	if (slash_rev != NULL)
	{
		*slash_rev = '\0';
		content_id=slash_rev+1;
	}
	
	char *lastdot = strrchr (content_id, '.');
	if (lastdot != NULL)
		*lastdot = '\0';
	
		
	uint8_t idps[0x10];
	aes_context aes_ctxt;
	uint8_t idps_const[0x10]={0x5E,0x06,0xE0,0x4F,0xD9,0x4A,0x71,0xBF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
	uint8_t rif_key_const[0x10]={0xDA,0x7D,0x4B,0x5E,0x49,0x9A,0x4F,0x53,0xB1,0xC1,0xA1,0x4A,0x74,0x84,0x44,0x3B};
		printf("reading:idps.hex\n");
	FILE *fp=fopen("idps.hex", "rb");
	if(!fp)
	{
		return -1;
	}
	fread(idps, 0x10, 1, fp);
	fclose(fp);
	uint8_t act_dat_key[0x10];
	uint8_t klicensee[0x10];
	uint8_t klicensee_enc_rif[0x10];
	uint8_t rap[0x10];
	uint64_t account_id;
	//uint8_t rifkey[0x10];
	fp=fopen("act.dat","rb");
	if(!fp)
	{
	//	fp=forge_act_dat();
		return -1;
	}
		printf("reading:act.dat\n");
	fseek(fp,0x8,SEEK_SET);
	fread(&account_id, 8,1,fp);//skip aa account need
	fseek(fp,0x10,SEEK_SET);
	fread(act_dat_key, 0x10,1,fp); //copy first key in primary table of act.dat
	fclose(fp);

	printf("reading:%s\n", path);
	fp=fopen(path, "rb");
	if(!fp)
	{
		return -1;
	}
	fread(rap, 0x10,1,fp);
	fclose(fp);
	uint8_t *rif=(uint8_t *)malloc(0x200);
	memset(rif,0,0x200);

	get_rif_key(rap, rif+0x50); //convert rap to rifkey(klicensee)
	aes_setkey_enc(&aes_ctxt, idps, IDPS_KEYBITS);
	aes_crypt_ecb(&aes_ctxt, AES_ENCRYPT, idps_const, idps_const);
	
	aes_setkey_dec(&aes_ctxt, idps_const, IDPS_KEYBITS);
	aes_crypt_ecb(&aes_ctxt, AES_DECRYPT, act_dat_key, act_dat_key);
	
	
	aes_setkey_enc(&aes_ctxt, act_dat_key, ACT_DAT_KEYBITS);
	aes_crypt_ecb(&aes_ctxt, AES_ENCRYPT, rif+0x50, rif+0x50);//encrypt rif with act.dat first key primary key table
	
	uint8_t index_act_key[4]={0};//very first key in act.dat primary table
	uint8_t index_act_key_enc[0x10];
	aes_setkey_enc(&aes_ctxt, rif_key_const, RIF_KEYBITS);
	aes_crypt_ecb(&aes_ctxt, AES_ENCRYPT, rif+0x40, rif+0x40);
	uint64_t timestamp=0x1619BF6DDCA; //today
	timestamp=swap_uint64(timestamp);
	uint32_t version_number=1;
	version_number=swap_uint32(version_number);
	uint32_t license_type=0x00010002;
	license_type=swap_uint32(license_type);
	uint64_t expiration_time=0;
	expiration_time=swap_uint64(expiration_time);
	memcpy(rif, &version_number,4);
	memcpy(rif+4, &license_type,4);
	memcpy(rif+8,&account_id,8);
	memcpy(rif+0x10, content_id, 0x24);
//	memcpy(rif+0x40, index_act_key_enc, 0x10);
//	memcpy(rif+0x50, klicensee_enc_rif,0x10);
	memcpy(rif+0x60, &timestamp, 8);
	memcpy(rif+0x68, &expiration_time,8);
	uint8_t sha1_digest[20];
	sha1(rif, 0x70,sha1_digest);
	ecdsa_set_curve();
	ecdsa_set_pub();
	ecdsa_set_priv();
	uint8_t R[0x15];
	uint8_t S[0x15];
	ecdsa_sign(sha1_digest, R, S);
	memcpy(rif+0x70, R+1, 0x14);
	memcpy(rif+0x70+0x14, S+1, 0x14);
	sha1(rif, 0xa0,sha1_digest);
	memcpy(rif+0xa0, sha1_digest,0x10);
	memcpy(rif+0xb0, sha1_digest,0x10);
	memset(rif+0xc0, 0, 0x40);
	_fill_rand_bytes(rif+0x100, 0x100);

	strcpy(path+strlen(path)-4, ".rif");
	printf("writing:%s\n", path);
	fp=fopen(path, "wb");
	fwrite(rif, 0x98,1,fp); //only needed till here
	fclose(fp);
		return 0;
}

int read_rif_key(char *content_id, uint8_t *rifkey)
{
	uint8_t idps[0x10];
	aes_context aes_ctxt;
	uint8_t idps_const[0x10]={0x5E,0x06,0xE0,0x4F,0xD9,0x4A,0x71,0xBF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
	uint8_t rif_key_const[0x10]={0xDA,0x7D,0x4B,0x5E,0x49,0x9A,0x4F,0x53,0xB1,0xC1,0xA1,0x4A,0x74,0x84,0x44,0x3B};
		printf("reading:idps.hex\n");
	FILE *fp=fopen("idps.hex", "rb");
	if(!fp)
	{
		return -1;
	}
	fread(idps, 0x10, 1, fp);
	fclose(fp);
	uint8_t act_dat_key[0x10];
	uint8_t klicensee[0x10];
	uint8_t klicensee_enc_rif[0x10];
	uint8_t rap[0x10];
	fp=fopen("act.dat","rb");
	if(!fp)
	{
		return -1;
	}
		printf("reading:act.dat\n");
	fseek(fp,0x8,SEEK_SET);
	fseek(fp,0x10,SEEK_SET);
	fread(act_dat_key, 0x10,1,fp); //copy first key in primary table of act.dat
	fclose(fp);
	char rap_path[0x80];
	strcpy(rap_path, content_id);
	strcat(rap_path, ".rap");
	printf("reading:%s\n", rap_path);
	fp=fopen(rap_path, "rb");
	if(!fp)
	{
		return -1;
	}
	fread(rap, 0x10,1,fp);
	fclose(fp);
	uint8_t *rif=(uint8_t *)malloc(0x200);
	memset(rif,0,0x200);

	get_rif_key(rap, rifkey); //convert rap to rifkey(klicensee)
	return 0;
}

u8 ps2_iv[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };


int sign_act_dat()
{
	uint8_t *act_dat_buf=(uint8_t *)malloc(0x2000);
	printf("reading:act.dat\n");
	FILE *fp=fopen("act.dat","rb");
	fread(act_dat_buf, 0x1038,1,fp);
	fclose(fp);
	uint8_t digest[20];
	sha1(act_dat_buf, 0x1010, digest);
	uint8_t R[0x15];
	uint8_t S[0x15];
	ecdsa_sign(digest, R,S);
	memcpy(act_dat_buf+0x1010, R+1, 0x14);
	memcpy(act_dat_buf+0x1010+0x14, S+1, 0x14);
	printf("writing:signed_act.dat\n");
	fp=fopen("signed_act.dat","wb");
	fwrite(act_dat_buf, 0x1038,1,fp);
	fclose(fp);
	return 0;
}

static void set_ps2_iv(u8 iv[])
{
	memcpy(iv, ps2_iv, 0x10);
}

static inline u32 be32(u8 *p)
{
	u32 a;

	a  = p[0] << 24;
	a |= p[1] << 16;
	a |= p[2] <<  8;
	a |= p[3] <<  0;

	return a;
}

static inline u32 le32(u8 *p)
{
	u32 a;

	a  = p[3] << 24;
	a |= p[2] << 16;
	a |= p[1] <<  8;
	a |= p[0] <<  0;

	return a;
}

static inline u64 be64(u8 *p)
{
	u32 a, b;

	a = be32(p);
	b = be32(p + 4);

	return ((u64)a<<32) | b;
}


void dump_meta(char mode[], FILE *in, char meta_file[], uint8_t *klicensee)
{
#define PS2_META_SEGMENT_START		1
#define PS2_DATA_SEGMENT_START		2
#define PS2_DEFAULT_SEGMENT_SIZE	0x4000
#define PS2_META_ENTRY_SIZE		0x20
	u8 ps2_key_cex_meta[] = { 0x38, 0x9D, 0xCB, 0xA5, 0x20, 0x3C, 0x81, 0x59, 0xEC, 0xF9, 0x4C, 0x93, 0x93, 0x16, 0x4C, 0xC9 };
	u8 ps2_key_cex_data[] = { 0x10, 0x17, 0x82, 0x34, 0x63, 0xF4, 0x68, 0xC1, 0xAA, 0x41, 0xD7, 0x00, 0xB1, 0x40, 0xF2, 0x57 };
	u8 ps2_key_cex_vmc[] = { 0x64, 0xE3, 0x0D, 0x19, 0xA1, 0x69, 0x41, 0xD6, 0x77, 0xE3, 0x2E, 0xEB, 0xE0, 0x7F, 0x45, 0xD2 };
	FILE * meta_out;

	u8 ps2_key_dex_meta[] = { 0x2B, 0x05, 0xF7, 0xC7, 0xAF, 0xD1, 0xB1, 0x69, 0xD6, 0x25, 0x86, 0x50, 0x3A, 0xEA, 0x97, 0x98 };
u8 ps2_key_dex_data[] = { 0x74, 0xFF, 0x7E, 0x5D, 0x1D, 0x7B, 0x96, 0x94, 0x3B, 0xEF, 0xDC, 0xFA, 0x81, 0xFC, 0x20, 0x07 };
u8 ps2_key_dex_vmc[] = { 0x30, 0x47, 0x9D, 0x4B, 0x80, 0xE8, 0x9E, 0x2B, 0x59, 0xE5, 0xC9, 0x14, 0x5E, 0x10, 0x64, 0xA9 };
u8 ps2_data_key[0x10];
	u8 ps2_meta_key[0x10];
	u8 iv[0x10];

	int segment_size;
	s64 data_size;
	int i;
	u8 header[256];
	u8 * data_buffer;
	u8 * meta_buffer;
	u32 read = 0;
	int num_child_segments;

	//open files
	meta_out = fopen(meta_file, "wb");

	//get file info
	read = fread(header, 256, 1, in);
	segment_size = be32(header + 0x84);
	data_size = be64(header + 0x88);
	num_child_segments = segment_size / PS2_META_ENTRY_SIZE;

	printf("segment size: %x\ndata_size: %llx\n\n", segment_size, data_size);

	//alloc buffers
	data_buffer = (u8 *)malloc(segment_size*num_child_segments);
	meta_buffer = (u8 *)malloc(segment_size);

	//generate keys
	if(strcmp(mode, "cex") == 0)
	{
		printf("cex\n");
		set_ps2_iv(iv);
		aescbc128_encrypt(ps2_key_cex_data, iv, klicensee, ps2_data_key, 0x10);
		aescbc128_encrypt(ps2_key_cex_meta, iv, klicensee, ps2_meta_key, 0x10);
	}else{
		printf("dex\n");
		set_ps2_iv(iv);
		aescbc128_encrypt(ps2_key_dex_data, iv, klicensee, ps2_data_key, 0x10);
		aescbc128_encrypt(ps2_key_dex_meta, iv, klicensee, ps2_meta_key, 0x10);
	}


	//decrypt iso
	fseek(in, segment_size, SEEK_SET);

	while(read = fread(meta_buffer, 1, segment_size, in))
	{
		//decrypt meta
		aescbc128_decrypt(ps2_meta_key, iv, meta_buffer, meta_buffer, read);
		fwrite(meta_buffer, read, 1, meta_out);
		read = fread(data_buffer, 1, segment_size*num_child_segments, in);
	}

	//cleanup
	free(data_buffer);
	free(meta_buffer);

	fclose(meta_out);
	fseek(in, 0, SEEK_SET);
}

int sign_enc(FILE *fp)
{
	uint8_t *buf=(uint8_t *)malloc(0x200);
	memset(buf,0,0x200);
	fread(buf, 0x100,1,fp);
	uint8_t R[0x15];
	uint8_t S[0x15];
	uint8_t digest[20];
	sha1(buf, 0xd8, digest);
	ecdsa_sign(digest,R,S);
	fseek(fp, 0xD8, SEEK_SET);
	fwrite(R+1, 0x14,1,fp);
	fwrite(S+1,0x14,1,fp);
	return 0;
}

static inline void wbe32(u8 *p, u32 v)
{
	p[0] = v >> 24;
	p[1] = v >> 16;
	p[2] = v >>  8;
	p[3] = v;
}

static inline void wbe64(u8 *p, u64 v)
{
	wbe32(p + 4, v);
	v >>= 32;
	wbe32(p, v);
}

#include <openssl/sha.h>
#include "pkg2zip_aes_x86.h"

static void decrypt_debug_pkg_normal(uint8_t *pkg, uint64_t size, uint64_t offset)
{
	u8 key[0x40];
	u8 bfr[0x1c];
	u64 i;

	memset(key, 0, sizeof key);
	memcpy(key, pkg + 0x60, 8);
	memcpy(key + 0x08, pkg + 0x60, 8);
	memcpy(key + 0x10, pkg + 0x60 + 0x08, 8);
	memcpy(key + 0x18, pkg + 0x60 + 0x08, 8);

	sha1(key, sizeof key, bfr);

	for (i = 0; i < size; i++) {
			if (i != 0 && (i % 16) == 0) {
				wbe64(key + 0x38, be64(key + 0x38) + 1);	
				sha1(key, sizeof key, bfr);
			}
			pkg[offset + i] ^= bfr[i & 0xf];
			if(i%(100*1024*1024)==0)
			{
				munmap(pkg-100*1024*1024+i, 100*1024*1024);
			}
		}
}

static void decrypt_debug_pkg_sse(uint8_t *pkg, uint64_t size, uint64_t offset)
{
	u8 key[0x40];
	u8 bfr[0x1c];
	u64 i;

	memset(key, 0, sizeof key);
	memcpy(key, pkg + 0x60, 8);
	memcpy(key + 0x08, pkg + 0x60, 8);
	memcpy(key + 0x10, pkg + 0x60 + 0x08, 8);
	memcpy(key + 0x18, pkg + 0x60 + 0x08, 8);

	SHA1(key, sizeof key, bfr);

	region_xor_sse(pkg+offset,bfr, 0x10); 
	#pragma unroll
	for (i = 0x10; i < size; i+=0x10) {
			
			wbe64(key + 0x38, be64(key + 0x38) + 1);
			SHA1(key, sizeof key, bfr);
			
			region_xor_sse(pkg+offset+i,bfr, 0x10); 
			if(i%(100*1024*1024)==0)
			{
				munmap(pkg-100*1024*1024+i, 100*1024*1024);
			}
		}
}

static void decrypt_debug_pkg(uint8_t *pkg, uint64_t size, uint64_t offset_data)
{
	if(aes128_supported_x86())
	{
		decrypt_debug_pkg_sse(pkg,size,offset_data);
	}
	else
	{
		decrypt_debug_pkg_normal(pkg,size,offset_data);
	}
}

int decrypt_retail_pkg_data(uint8_t *buf, uint64_t size, uint8_t *data_riv, uint8_t *gpkg_key)
{
	aes128ctr(gpkg_key, data_riv, buf, size, buf);
	return 0;
}

static void check_ps2_pkg_patch(uint8_t *pkg, uint64_t offset)
{
	u64 i;
	u64 n_files;
	u32 fname_len;
	u32 fname_off;
	u64 file_offset;
	u32 flags;
	char fname[256];
	u8 *tmp;
	
	uint8_t digest[20];
	uint8_t R[0x15];
	uint8_t S[0x15];

	n_files = be32(pkg + 0x14);

	for (i = 0; i < n_files; i++) {
		tmp = pkg + offset + i*0x20;

		fname_off = be32(tmp) + offset;
		fname_len = be32(tmp + 0x04);
		file_offset = be64(tmp + 0x08) + offset;
		uint64_t size = be64(tmp + 0x10);
		flags = be32(tmp + 0x18);
		if (fname_len >= sizeof fname)
			printf("filename too long: %s\n", pkg + fname_off);

		memset(fname, 0, sizeof fname);
		strncpy(fname, (char *)(pkg + fname_off), fname_len);
		printf("%s\n", fname);

	//		if((strstr(fname, "ISO.BIN.ENC")) || (strstr(fname, "ISO.BIN.EDAT")) || (strstr(fname, "CONFIG")) || (strstr(fname, "MINIS.EDAT"))
		//		|| (strstr(fname, "MINIS2.EDAT")) || (strstr(fname, "drm.edat")) || (strstr(fname, "PSP.EDAT"))) //whitelist for the files to be signed  
			if((strstr(fname, ".edat")) || (strstr(fname, ".EDAT")) || (strstr(fname, "CONFIG")) || (strstr(fname, "ISO.BIN.ENC")))
			{
				printf("found %s..Resigning\n", fname);
				//sign_enc_buf(pkg+file_offset);
				sha1(pkg+file_offset+0x00, 0xd8, digest);
				ecdsa_sign(digest, R, S);
		
				memcpy(pkg+file_offset+0xd8, R+1, 0x14);
				memcpy(pkg+file_offset+0xd8+0x14, S+1, 0x14);
			}
	}
}

typedef struct __TOC_HEADER {
	uint32_t fname_offset;
	uint32_t name_size;
	uint64_t file_off;
	uint64_t file_size;
	uint8_t psp_key_type;
	uint8_t shit_stuff[7];
} TOC_HEADER;

int parse_psp_pkg(uint8_t *pkg, uint32_t toc_len, uint8_t *iv_const, uint32_t data_size, int file_out, uint64_t offset_data)
{
	TOC_HEADER *header=(TOC_HEADER *)malloc(2*1024*1024);
	uint8_t pkg_key[0x10]={0x2E,0x7B,0x71,0xD7,0xC9,0xC9,0xA1,0x4E,0xA3,0x22,0x1F,0x18,0x88,0x28,0xB8,0xF8};
	uint8_t pkg_key_psp[0x10]={0x07,0xF2,0xC6,0x82,0x90,0xB5,0x0D,0x2C,0x33,0x81,0x8D,0x70,0x9B,0x60,0xE6,0x2B};
	
	aes128_key ps3_key;
	aes128_init(&ps3_key, pkg_key);
	
	memcpy(header, pkg, toc_len);
	int i=0;
	int number_files=toc_len/0x20;
	uint8_t main_key[0x10];
	
	uint32_t len_dec_name=0;
	uint8_t second_last;
	uint8_t *tmp_buf=(uint8_t *)malloc(100*1024*1024);
	uint8_t name[4096]={0};

	for(i=0;i<number_files;i++)
	{
		header[i].fname_offset=swap_uint32(header[i].fname_offset);
		header[i].name_size=swap_uint32(header[i].name_size);
		header[i].file_off=swap_uint64(header[i].file_off);
		header[i].file_size=swap_uint64(header[i].file_size);

		if(header[i].psp_key_type==0x90)
		{
			memcpy(main_key, pkg_key_psp, 0x10);
		}
		else
		{
			memcpy(main_key, pkg_key, 0x10);
		}
		
		aes128_key key;
		aes128_init(&key, main_key);
				
		len_dec_name=header[i].name_size&0xf0;
		if(header[i].name_size&0xf)
		{
			len_dec_name+=0x10;
		}
		
		printf("len_dec_name=%x\n", len_dec_name);
		printf("header[i].fname_offset=%x\n", header[i].fname_offset);
		printf("header[i].file_off=%x\n", header[i].file_off);
		printf("header[i].file_size=%x\n", header[i].file_size);
		printf("number_files=%x\n", number_files);
		
		int loop=0;
		printf("key: ");

		for (loop = 0; loop < 0x10; loop++)
		{
			printf("%02X", main_key[loop]);
		}		
		printf("\n");

		loop=0;
		printf("iv: ");

		for (loop = 0; loop < 0x10; loop++)
		{
			printf("%02X", iv_const[loop]);
		}		
		printf("\n");
		
		memcpy(name, pkg+header[i].fname_offset, len_dec_name);
		aes128_ctr_xor(&key, iv_const, (header[i].fname_offset)/16, name, len_dec_name);
		lseek(file_out, header[i].fname_offset+offset_data, SEEK_SET);
		write(file_out, name, len_dec_name);
		
		if(header[i].file_size)
		{
			uint64_t loop=0;
			for(loop=0;loop<header[i].file_size;loop+=100*1024*1024)
			{
				if(header[i].file_size-loop<100*1024*1024)
				{
					lseek(file_out, header[i].file_off+offset_data+loop, SEEK_SET);
					read(file_out, tmp_buf, header[i].file_size-loop);
					aes128_ctr_xor(&key, iv_const, (header[i].file_off+loop)/16, tmp_buf, header[i].file_size-loop);
					lseek(file_out, header[i].file_off+offset_data+loop, SEEK_SET);
					write(file_out, tmp_buf, header[i].file_size-loop);
				}
				else
				{
					lseek(file_out, header[i].file_off+offset_data+loop, SEEK_SET);
					read(file_out, tmp_buf, 100*1024*1024);
					aes128_ctr_xor(&key, iv_const, (header[i].file_off+loop)/16, tmp_buf, 100*1024*1024);
					lseek(file_out, header[i].file_off+offset_data+loop, SEEK_SET);
					write(file_out, tmp_buf, 100*1024*1024);
				}
			}
		}
	}
	free(tmp_buf);
	return 0;
}

int parse_ps3_psp_pkg(uint8_t *pkg, uint32_t toc_len, uint8_t *iv_const)
{
	TOC_HEADER *header=(TOC_HEADER *)malloc(2*1024*1024);
	uint8_t pkg_key[0x10]={0x2E,0x7B,0x71,0xD7,0xC9,0xC9,0xA1,0x4E,0xA3,0x22,0x1F,0x18,0x88,0x28,0xB8,0xF8};
	uint8_t pkg_key_psp[0x10]={0x07,0xF2,0xC6,0x82,0x90,0xB5,0x0D,0x2C,0x33,0x81,0x8D,0x70,0x9B,0x60,0xE6,0x2B};
	
	aes128_key ps3_key;
	aes128_init(&ps3_key, pkg_key);
	
	memcpy(header, pkg, toc_len);
	int i=0;
	int number_files=toc_len/0x20;
	uint8_t main_key[0x10];
	
	uint32_t len_dec_name=0;
	uint8_t second_last;
	for(i;i<number_files;i++)
	{
		header[i].fname_offset=swap_uint32(header[i].fname_offset);
		header[i].name_size=swap_uint32(header[i].name_size);
		header[i].file_off=swap_uint64(header[i].file_off);
		header[i].file_size=swap_uint64(header[i].file_size);

		if(header[i].psp_key_type==0x90)
		{
			memcpy(main_key, pkg_key_psp, 0x10);
		}
		else
		{
			memcpy(main_key, pkg_key, 0x10);
		}
		
		aes128_key key;
		aes128_init(&key, main_key);
		
		if(header[i].name_size>0x10)
		{
			len_dec_name=0x20;
		}
		else if(header[i].name_size>0x20)
		{
			len_dec_name=0x30;
		}
		else
		{
			len_dec_name=0x10;
		}
		printf("len_dec_name=%x\n", len_dec_name);
		printf("header[i].fname_offset=%x\n", header[i].fname_offset);
		printf("header[i].file_off=%x\n", header[i].file_off);
		printf("header[i].file_size=%x\n", header[i].file_size);
		printf("number_files=%x\n", number_files);
		
		int loop=0;
		printf("key: ");

		for (loop = 0; loop < 0x10; loop++)
		{
			printf("%02X", main_key[loop]);
		}		
		printf("\n");

		loop=0;
		printf("iv: ");

		for (loop = 0; loop < 0x10; loop++)
		{
			printf("%02X", iv_const[loop]);
		}		
		printf("\n");
		
	//	aes128ctrxor(main_key, iv_const, pkg+header[i].fname_offset, len_dec_name, pkg+header[i].fname_offset,header[i].fname_offset-toc_len);
		aes128_ctr_xor(&key, iv_const, ((header[i].fname_offset)-toc_len)/16, pkg+header[i].fname_offset, len_dec_name);
		aes128_ctr_xor(&key, iv_const, ((header[i].file_off)-toc_len)/16, pkg+header[i].file_off, header[i].file_size);
		
	//	aes128ctrxor(main_key, iv_const, pkg+header[i].file_off, header[i].file_size, pkg+header[i].file_off,header[i].file_off-toc_len);
	}
	return 0;
}

int main(int argc, char *argv[])
{
	if(argc<2)
	{
		goto done;
	}
	
if((strstr(argv[1], ".rap")) || (strstr(argv[1], ".RAP")))
	{
		if(read_act_dat_and_make_rif(argv[1])==0)
		{
			sign_act_dat();
			printf("\nits done!\npress enter\n");
		}
		else
		{
			printf("\nverify your files!");
		}
		getchar();
		getchar();
		return 0;
	}
	else if((strstr(argv[1], ".EDAT")) || (strstr(argv[1], ".edat")))
	{
		char *slash2 = strrchr (argv[1], '\\');
		if (slash2 != NULL)
		{
			*slash2 = '\0';
			argv[1]=slash2+1;
		}
		FILE *fp=fopen(argv[1], "rb+");
		if(!fp)
		{
			printf("edat unreadable!\n");
		}

		uint32_t license;
		char *content_id_edat=(char *)malloc(0x100);
		memset(content_id_edat,0,0x100);
		fread(content_id_edat, 0x34, 1,fp);
		memcpy(&license, content_id_edat+8, 4);
		license=swap_uint32(license);
		content_id_edat+=0x10;
		uint8_t rifkey[0x10];

/*OLD METHOD!!!!!*/
/*		if((license==2) || (license==3))
		{
			read_rif_key(content_id_edat, rifkey);
		}
		uint8_t meta_sig_hash_output[20];
		uint8_t header_sig_hash_output[20];
		unsigned char devklic_edat[16] = {0x52,0xC0,0xB5,0xCA,0x76,0xD6,0x13,0x4B,0xB4,0x5F,0xC6,0x6C,0xA6,0x37,0xF2,0xC1};

		FILE *devklic_explicit=fopen("devklic", "rb");
		if(devklic_explicit)
		{
			printf("using explicit devklic\n");
			fread(devklic_edat, 16, 1, devklic_explicit);
			fclose(devklic_explicit);
		}
		
		if(extract_data_and_sign(fp, devklic_edat, rifkey, 0))
		{
			getchar();
			return -1;
		}
*/
/*END*/		
/* NEW METHOD!!!!!!!!*/
		ecdsa_set_curve();
		ecdsa_set_pub();
		ecdsa_set_priv();
		fseek(fp,0,SEEK_SET);
		sign_enc(fp);
/*END*/
		fclose(fp);
		printf("edat resigned!\n");
		fp=fopen("ISO.BIN.ENC", "rb+");
		if(fp)
		{
		//	dump_meta((char *)"cex", fp, (char *)"ISO.BIN.ENC_meta_out", rifkey);
			sign_enc(fp);
			printf("enc resigned!\n");
			fclose(fp);
			fp=fopen("CONFIG", "rb+");
			if(fp)
			{
				sign_enc(fp);
				printf("config resigned!\n");
				fclose(fp);
			}
		}
		getchar();
        getchar();
		return 0;
	}
	else if((strstr(argv[1], ".pkg")) || (strstr(argv[1], ".PKG")))
	{
		ecdsa_set_curve();
		ecdsa_set_pub();
		ecdsa_set_priv();
		FILE *fp=fopen(argv[1], "rb+");
		if(!fp)
		{
			printf("cant open file!\n");
			return -1;
		}
		uint64_t len=0;
		fseek(fp,0,SEEK_END);
		len=ftell(fp);
		printf("size:%x\n", len);
		fseek(fp,0,SEEK_SET);
		fclose(fp);
		
		int fd=open(argv[1], O_RDONLY);
		uint8_t *buf2=(uint8_t *)mmap(0, len, PROT_READ, MAP_SHARED, fd, 0);
		char out_path[4096];
		strcpy(out_path, argv[1]);
		strcat(out_path, "_signed.pkg");
		int fd_out=open(out_path, O_RDWR|O_CREAT);
		lseek(fd_out, 0, SEEK_SET);
		printf("making backup\n");
		uint64_t bkp=0;
		for(bkp;bkp<len;bkp+=100*1024*1024)
		{
			if(len-bkp<100*1024*1024)
			{
				write(fd_out, buf2+bkp, len-bkp);
				munmap(buf2+bkp, len-bkp);
			}
			else
			{
				printf("bkp:%016llx\n", bkp);
				lseek(fd_out, bkp, SEEK_SET);
				write(fd_out, buf2+bkp, 100*1024*1024);
				munmap(buf2+bkp, 100*1024*1024);
			}
		}
			
		close(fd);
		uint8_t *buf=(uint8_t *)mmap(0, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd_out, 0);
		
		if(!buf)
		{
			printf("not enough free memory!\n");
			return -1;
		}
		uint64_t data_size=*(uint64_t *)(buf+0x28);
		uint8_t iv[0x10];
		uint64_t offset_data=*(uint64_t *)(buf+0x20);
		offset_data=swap_uint64(offset_data);
		uint32_t pkg_info_offset=*(uint32_t *)(buf+0x8);
		pkg_info_offset=swap_uint32(pkg_info_offset);
		uint32_t header_size=*(uint32_t *)(buf+0x10);
		header_size=swap_uint32(header_size);
		uint32_t toc_size=(swap_uint32(*(uint32_t *)(buf+0x14)))*0x20;	
		memcpy(iv, buf+0x70, 0x10);
		uint8_t iv_bkp[0x10];
		memcpy(iv_bkp, iv, 0x10);
		data_size=swap_uint64(data_size);
			uint8_t pkg_key[0x10]={0x2E,0x7B,0x71,0xD7,0xC9,0xC9,0xA1,0x4E,0xA3,0x22,0x1F,0x18,0x88,0x28,0xB8,0xF8};
			uint8_t pkg_key_psp[0x10]={0x07,0xF2,0xC6,0x82,0x90,0xB5,0x0D,0x2C,0x33,0x81,0x8D,0x70,0x9B,0x60,0xE6,0x2B};
		if(*(uint8_t *)&buf[4]!=0x80)
		{
			*(uint8_t *)&buf[4]=0x80;
			uint8_t retail_flag=0x80;
			if(argv[2])
			{
				if(strstr(argv[2], "psp"))
				{
					*(uint8_t *)&buf[7]=2; //type psp set
					printf("PSP flag set!\n");
				}
			}
			else
			{	
				char is_minis_psx[0x20]={"yes"};
				char user_input[0x20];
				printf("Is this pkg type psp minis or psx?if so, type \"yes\"(without quotes) otherwise type anything else:");
				scanf("%s", &user_input); //popular tools resign as type PS3 DEBUG even if minis/psx
				printf("\n");
				if(strcmp(is_minis_psx, user_input)==0)
				{
					*(uint8_t *)&buf[7]=2; //type psp set
					printf("PSP flag set!\n");
				}
			}
			printf("decrypting debug pkg\n");
			decrypt_debug_pkg(buf, data_size, offset_data);
			munmap(buf, len);
			
			buf=(uint8_t *)mmap(0, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd_out, 0);
			
			printf("encrypting retail pkg\n");
			check_ps2_pkg_patch(buf, offset_data);
			if(*(uint8_t *)&buf[7]==2)
			{
				memcpy(iv, iv_bkp, 0x10);
				parse_psp_pkg(buf+offset_data, toc_size, iv, data_size, fd_out, offset_data);
				munmap(buf, len);
				buf=(uint8_t *)mmap(0, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd_out, 0);
			
				memcpy(iv, iv_bkp, 0x10);
				decrypt_retail_pkg_data(buf+offset_data, toc_size, iv, pkg_key_psp);
				memcpy(iv, iv_bkp, 0x10);
			}
			else
			{
				memcpy(iv, iv_bkp, 0x10);
				parse_psp_pkg(buf+offset_data, toc_size, iv, data_size, fd_out, offset_data);
				munmap(buf, len);
				buf=(uint8_t *)mmap(0, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd_out, 0);
			
				memcpy(iv, iv_bkp, 0x10);
				decrypt_retail_pkg_data(buf+offset_data, toc_size, iv, pkg_key);
			}
			cmac_hash_forge(pkg_key, 0x10, buf, 0x80, buf+0x80);
		}
		else
		{
			printf("decrypting retail pkg\n");
			if(*(uint8_t *)&buf[7]==2)
			{
				printf("type psp detected\n");
				decrypt_retail_pkg_data(buf+offset_data, toc_size, iv, pkg_key_psp);
				memcpy(iv, iv_bkp, 0x10);
				parse_psp_pkg(buf+offset_data, toc_size, iv, data_size, fd_out, offset_data);
				munmap(buf, len);
				buf=(uint8_t *)mmap(0, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd_out, 0);
			
			}
			else
			{
				memcpy(iv, iv_bkp, 0x10);
				decrypt_retail_pkg_data(buf+offset_data, toc_size, iv, pkg_key);
				memcpy(iv, iv_bkp, 0x10);
				parse_psp_pkg(buf+offset_data, toc_size, iv, data_size, fd_out, offset_data);
				munmap(buf, len);
				buf=(uint8_t *)mmap(0, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd_out, 0);
			
				memcpy(iv, iv_bkp, 0x10);
			}
			printf("encrypting retail pkg\n");
			check_ps2_pkg_patch(buf, offset_data);
			
			if(*(uint8_t *)&buf[7]==2)
			{
				parse_psp_pkg(buf+offset_data, toc_size, iv, data_size, fd_out, offset_data);
				munmap(buf, len);
				buf=(uint8_t *)mmap(0, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd_out, 0);
			
				memcpy(iv, iv_bkp,0x10);
				decrypt_retail_pkg_data(buf+offset_data, toc_size, iv, pkg_key_psp);
			}
			else
			{
				memcpy(iv, iv_bkp,0x10);
				parse_psp_pkg(buf+offset_data, toc_size, iv, data_size, fd_out, offset_data);
				munmap(buf, len);
				buf=(uint8_t *)mmap(0, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd_out, 0);
			
				memcpy(iv, iv_bkp,0x10);
				decrypt_retail_pkg_data(buf+offset_data, toc_size, iv, pkg_key);
			}
			cmac_hash_forge(pkg_key, 0x10, buf, 0x80, buf+0x80);
		}
		
		uint8_t digest[20];
		uint8_t R[0x15];
		uint8_t S[0x15];

		cmac_hash_forge(pkg_key, 0x10, buf+pkg_info_offset, header_size-0x40, buf+pkg_info_offset+header_size-0x40);

		munmap(buf, len);
		buf=(uint8_t *)mmap(0, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd_out, 0);
		
		SHA_CTX ctx;

		SHA1_Init( &ctx );
		uint64_t sha1_loop=0;
		for(sha1_loop;sha1_loop<len-0x20;sha1_loop+=100*1024*1024)
		{
			if(len-sha1_loop-0x20<100*1024*1024)
			{
				SHA1_Update( &ctx, buf+sha1_loop, len-sha1_loop-0x20 );
				SHA1_Final(buf+len-0x20, &ctx);
				munmap(buf+sha1_loop, len-sha1_loop);
			}
			else
			{
				SHA1_Update(&ctx, buf+sha1_loop, 100*1024*1024);
				munmap(buf+sha1_loop, 100*1024*1024);
			}
		}
	
		munmap(buf, len);
		close(fd_out);
		chmod(out_path, 0777);
		printf("pkg signed!\n");
		getchar();
		getchar();
		return 0;
	}
	else if(strstr(argv[1], ".ENC"))
	{
		ecdsa_set_curve();
		ecdsa_set_pub();
		ecdsa_set_priv();
		FILE *fp=fopen(argv[1], "rb+");
		sign_enc(fp);
		printf("enc resigned!\n");
		fclose(fp);
		fp=fopen("CONFIG", "rb+");
		if(fp)
		{
			sign_enc(fp);
			printf("config resigned!\n");
			fclose(fp);
		}
		getchar();
		getchar();
	}
	
done:
	printf("no valid option or no valid file provided!\n");
	getchar();
	getchar();
	return -1;
}
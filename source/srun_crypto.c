//
// Created by TigGrak on 2026/3/15.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// ==========================================
// 1. MD5 & HMAC-MD5 Implementation
// ==========================================
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))
#define FF(a, b, c, d, x, s, ac) { (a) += F((b), (c), (d)) + (x) + (uint32_t)(ac); (a) = ROTATE_LEFT((a), (s)); (a) += (b); }
#define GG(a, b, c, d, x, s, ac) { (a) += G((b), (c), (d)) + (x) + (uint32_t)(ac); (a) = ROTATE_LEFT((a), (s)); (a) += (b); }
#define HH(a, b, c, d, x, s, ac) { (a) += H((b), (c), (d)) + (x) + (uint32_t)(ac); (a) = ROTATE_LEFT((a), (s)); (a) += (b); }
#define II(a, b, c, d, x, s, ac) { (a) += I((b), (c), (d)) + (x) + (uint32_t)(ac); (a) = ROTATE_LEFT((a), (s)); (a) += (b); }

typedef struct { uint32_t state[4]; uint32_t count[2]; unsigned char buffer[64]; } MD5_CTX;

static void MD5Transform(uint32_t state[4], const unsigned char block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], x[16];
    for(int i=0, j=0; j<64; i++, j+=4)
        x[i] = ((uint32_t)block[j]) | (((uint32_t)block[j+1])<<8) | (((uint32_t)block[j+2])<<16) | (((uint32_t)block[j+3])<<24);
    FF(a, b, c, d, x[ 0], 7, 0xd76aa478); FF(d, a, b, c, x[ 1], 12, 0xe8c7b756); FF(c, d, a, b, x[ 2], 17, 0x242070db); FF(b, c, d, a, x[ 3], 22, 0xc1bdceee);
    FF(a, b, c, d, x[ 4], 7, 0xf57c0faf); FF(d, a, b, c, x[ 5], 12, 0x4787c62a); FF(c, d, a, b, x[ 6], 17, 0xa8304613); FF(b, c, d, a, x[ 7], 22, 0xfd469501);
    FF(a, b, c, d, x[ 8], 7, 0x698098d8); FF(d, a, b, c, x[ 9], 12, 0x8b44f7af); FF(c, d, a, b, x[10], 17, 0xffff5bb1); FF(b, c, d, a, x[11], 22, 0x895cd7be);
    FF(a, b, c, d, x[12], 7, 0x6b901122); FF(d, a, b, c, x[13], 12, 0xfd987193); FF(c, d, a, b, x[14], 17, 0xa679438e); FF(b, c, d, a, x[15], 22, 0x49b40821);
    GG(a, b, c, d, x[ 1], 5, 0xf61e2562); GG(d, a, b, c, x[ 6], 9, 0xc040b340); GG(c, d, a, b, x[11], 14, 0x265e5a51); GG(b, c, d, a, x[ 0], 20, 0xe9b6c7aa);
    GG(a, b, c, d, x[ 5], 5, 0xd62f105d); GG(d, a, b, c, x[10], 9,  0x2441453); GG(c, d, a, b, x[15], 14, 0xd8a1e681); GG(b, c, d, a, x[ 4], 20, 0xe7d3fbc8);
    GG(a, b, c, d, x[ 9], 5, 0x21e1cde6); GG(d, a, b, c, x[14], 9, 0xc33707d6); GG(c, d, a, b, x[ 3], 14, 0xf4d50d87); GG(b, c, d, a, x[ 8], 20, 0x455a14ed);
    GG(a, b, c, d, x[13], 5, 0xa9e3e905); GG(d, a, b, c, x[ 2], 9, 0xfcefa3f8); GG(c, d, a, b, x[ 7], 14, 0x676f02d9); GG(b, c, d, a, x[12], 20, 0x8d2a4c8a);
    HH(a, b, c, d, x[ 5], 4, 0xfffa3942); HH(d, a, b, c, x[ 8], 11, 0x8771f681); HH(c, d, a, b, x[11], 16, 0x6d9d6122); HH(b, c, d, a, x[14], 23, 0xfde5380c);
    HH(a, b, c, d, x[ 1], 4, 0xa4beea44); HH(d, a, b, c, x[ 4], 11, 0x4bdecfa9); HH(c, d, a, b, x[ 7], 16, 0xf6bb4b60); HH(b, c, d, a, x[10], 23, 0xbebfbc70);
    HH(a, b, c, d, x[13], 4, 0x289b7ec6); HH(d, a, b, c, x[ 0], 11, 0xeaa127fa); HH(c, d, a, b, x[ 3], 16, 0xd4ef3085); HH(b, c, d, a, x[ 6], 23,  0x4881d05);
    HH(a, b, c, d, x[ 9], 4, 0xd9d4d039); HH(d, a, b, c, x[12], 11, 0xe6db99e5); HH(c, d, a, b, x[15], 16, 0x1fa27cf8); HH(b, c, d, a, x[ 2], 23, 0xc4ac5665);
    II(a, b, c, d, x[ 0], 6, 0xf4292244); II(d, a, b, c, x[ 7], 10, 0x432aff97); II(c, d, a, b, x[14], 15, 0xab9423a7); II(b, c, d, a, x[ 5], 21, 0xfc93a039);
    II(a, b, c, d, x[12], 6, 0x655b59c3); II(d, a, b, c, x[ 3], 10, 0x8f0ccc92); II(c, d, a, b, x[10], 15, 0xffeff47d); II(b, c, d, a, x[ 1], 21, 0x85845dd1);
    II(a, b, c, d, x[ 8], 6, 0x6fa87e4f); II(d, a, b, c, x[15], 10, 0xfe2ce6e0); II(c, d, a, b, x[ 6], 15, 0xa3014314); II(b, c, d, a, x[13], 21, 0x4e0811a1);
    II(a, b, c, d, x[ 4], 6, 0xf7537e82); II(d, a, b, c, x[11], 10, 0xbd3af235); II(c, d, a, b, x[ 2], 15, 0x2ad7d2bb); II(b, c, d, a, x[ 9], 21, 0xeb86d391);
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}
static void MD5Init(MD5_CTX *context) {
    context->count[0] = context->count[1] = 0;
    context->state[0] = 0x67452301; context->state[1] = 0xefcdab89;
    context->state[2] = 0x98badcfe; context->state[3] = 0x10325476;
}
static void MD5Update(MD5_CTX *context, const unsigned char *input, unsigned int inputLen) {
    unsigned int i, index, partLen;
    index = (unsigned int)((context->count[0] >> 3) & 0x3F);
    if ((context->count[0] += ((uint32_t)inputLen << 3)) < ((uint32_t)inputLen << 3)) context->count[1]++;
    context->count[1] += ((uint32_t)inputLen >> 29);
    partLen = 64 - index;
    if (inputLen >= partLen) {
        memcpy(&context->buffer[index], input, partLen);
        MD5Transform(context->state, context->buffer);
        for (i = partLen; i + 63 < inputLen; i += 64) MD5Transform(context->state, &input[i]);
        index = 0;
    } else i = 0;
    memcpy(&context->buffer[index], &input[i], inputLen - i);
}
static void MD5Final(unsigned char digest[16], MD5_CTX *context) {
    unsigned char bits[8];
    unsigned int index, padLen;
    for(int i=0; i<8; i++) bits[i] = (unsigned char)((context->count[i<4?0:1] >> ((i%4)*8)) & 0xff);
    index = (unsigned int)((context->count[0] >> 3) & 0x3f);
    padLen = (index < 56) ? (56 - index) : (120 - index);
    static const unsigned char PADDING[64] = {0x80};
    MD5Update(context, PADDING, padLen);
    MD5Update(context, bits, 8);
    for (int i = 0; i < 16; i++) digest[i] = (unsigned char)((context->state[i>>2] >> ((i%4)*8)) & 0xff);
}
void hmac_md5(const unsigned char *key, int key_len, const unsigned char *text, int text_len, unsigned char *digest) {
    MD5_CTX context;
    unsigned char k_ipad[64], k_opad[64], tk[16];
    if (key_len > 64) {
        MD5Init(&context); MD5Update(&context, key, key_len); MD5Final(tk, &context);
        key = tk; key_len = 16;
    }
    memset(k_ipad, 0, 64); memset(k_opad, 0, 64);
    memcpy(k_ipad, key, key_len); memcpy(k_opad, key, key_len);
    for (int i = 0; i < 64; i++) { k_ipad[i] ^= 0x36; k_opad[i] ^= 0x5c; }
    MD5Init(&context); MD5Update(&context, k_ipad, 64); MD5Update(&context, text, text_len); MD5Final(digest, &context);
    MD5Init(&context); MD5Update(&context, k_opad, 64); MD5Update(&context, digest, 16); MD5Final(digest, &context);
}

// ==========================================
// 2. SHA1 Implementation
// ==========================================
#define SHA1ROL(value, bits) (((value) << (bits)) | (((value) & 0xffffffff) >> (32 - (bits))))
#define SHA1BLK(i) (block->l[i&15] = SHA1ROL(block->l[(i+13)&15]^block->l[(i+8)&15]^block->l[(i+2)&15]^block->l[i&15],1))
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+block->l[i]+0x5a827999+SHA1ROL(v,5);w=SHA1ROL(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+SHA1BLK(i)+0x5a827999+SHA1ROL(v,5);w=SHA1ROL(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+SHA1BLK(i)+0x6ed9eba1+SHA1ROL(v,5);w=SHA1ROL(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+SHA1BLK(i)+0x8f1bbcdc+SHA1ROL(v,5);w=SHA1ROL(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+SHA1BLK(i)+0xca62c1d6+SHA1ROL(v,5);w=SHA1ROL(w,30);

typedef struct { uint32_t state[5]; uint32_t count[2]; unsigned char buffer[64]; } SHA1_CTX;

static void SHA1Transform(uint32_t state[5], const unsigned char buffer[64]) {
    uint32_t a, b, c, d, e;
    typedef union { unsigned char c[64]; uint32_t l[16]; } CHAR64LONG16;
    CHAR64LONG16 block[1];
    for (int i = 0; i < 16; i++) {
        block->l[i] = (buffer[i*4]<<24)|(buffer[i*4+1]<<16)|(buffer[i*4+2]<<8)|(buffer[i*4+3]);
    }
    a = state[0]; b = state[1]; c = state[2]; d = state[3]; e = state[4];
    R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
    R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
    R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
    R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
    R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
    R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
    R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
    R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
    R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
    R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
    R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
    R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
    R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
    R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
    R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
    R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
    R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
    R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
    R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
    R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);
    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}
static void SHA1Init(SHA1_CTX *context) {
    context->state[0] = 0x67452301; context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE; context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0; context->count[0] = context->count[1] = 0;
}
static void SHA1Update(SHA1_CTX *context, const unsigned char *data, uint32_t len) {
    uint32_t i, j;
    j = context->count[0];
    if ((context->count[0] += len << 3) < j) context->count[1]++;
    context->count[1] += (len >> 29);
    j = (j >> 3) & 63;
    if ((j + len) > 63) {
        memcpy(&context->buffer[j], data, (i = 64 - j));
        SHA1Transform(context->state, context->buffer);
        for (; i + 63 < len; i += 64) SHA1Transform(context->state, &data[i]);
        j = 0;
    } else i = 0;
    memcpy(&context->buffer[j], &data[i], len - i);
}
static void SHA1Final(unsigned char digest[20], SHA1_CTX *context) {
    unsigned i; unsigned char finalcount[8]; unsigned char c;
    for (i = 0; i < 8; i++) {
        finalcount[i] = (unsigned char)((context->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);
    }
    c = 0200; SHA1Update(context, &c, 1);
    while ((context->count[0] & 504) != 448) { c = 0000; SHA1Update(context, &c, 1); }
    SHA1Update(context, finalcount, 8);
    for (i = 0; i < 20; i++) {
        digest[i] = (unsigned char)((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
    }
}
void get_sha1(const char *value, char *out_hex) {
    SHA1_CTX ctx;
    unsigned char digest[20];
    SHA1Init(&ctx);
    SHA1Update(&ctx, (const unsigned char*)value, strlen(value));
    SHA1Final(digest, &ctx);
    for (int i = 0; i < 20; i++) sprintf(out_hex + (i * 2), "%02x", digest[i]);
}

// ==========================================
// 3. Base64 Implementation
// ==========================================
char* get_base64(const unsigned char *s, int len) {
    const char alpha[] = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA";
    int imax = len - len % 3;
    char *res = (char*)malloc(len * 2 + 10);
    int res_len = 0;
    for (int i = 0; i < imax; i += 3) {
        uint32_t b10 = (s[i] << 16) | (s[i + 1] << 8) | s[i + 2];
        res[res_len++] = alpha[(b10 >> 18) & 63]; res[res_len++] = alpha[(b10 >> 12) & 63];
        res[res_len++] = alpha[(b10 >> 6) & 63]; res[res_len++] = alpha[b10 & 63];
    }
    if (len - imax == 1) {
        uint32_t b10 = s[imax] << 16;
        res[res_len++] = alpha[(b10 >> 18) & 63]; res[res_len++] = alpha[(b10 >> 12) & 63];
        res[res_len++] = '='; res[res_len++] = '=';
    } else if (len - imax == 2) {
        uint32_t b10 = (s[imax] << 16) | (s[imax + 1] << 8);
        res[res_len++] = alpha[(b10 >> 18) & 63]; res[res_len++] = alpha[(b10 >> 12) & 63];
        res[res_len++] = alpha[(b10 >> 6) & 63]; res[res_len++] = '=';
    }
    res[res_len] = '\0';
    return res;
}

// ==========================================
// 4. Xencode Implementation
// ==========================================
void sencode(const char *msg, int msg_len, uint32_t *pwd, int *pwd_len, int is_key) {
    int length = msg_len / 4 + ((msg_len % 4) ? 1 : 0);
    for (int i = 0; i < length; i++) pwd[i] = 0;
    for (int i = 0; i < msg_len; i++) pwd[i / 4] |= ((uint32_t)(unsigned char)msg[i]) << ((i % 4) * 8);
    if (is_key) { pwd[length] = msg_len; length++; }
    *pwd_len = length;
}
unsigned char* lencode(uint32_t *msg, int l, int is_key, int *out_len) {
    int ll = (l - 1) << 2;
    if (is_key) {
        uint32_t m = msg[l - 1];
        if (m < ll - 3 || m > ll) return NULL;
        ll = m;
    }
    unsigned char *res = (unsigned char*)malloc(l * 4);
    for (int i = 0; i < l; i++) {
        res[i * 4] = msg[i] & 0xff; res[i * 4 + 1] = (msg[i] >> 8) & 0xff;
        res[i * 4 + 2] = (msg[i] >> 16) & 0xff; res[i * 4 + 3] = (msg[i] >> 24) & 0xff;
    }
    *out_len = is_key ? ll : l * 4;
    return res;
}
unsigned char* get_xencode(const char *msg, const char *key, int *out_len) {
    if (msg == NULL || strlen(msg) == 0) { *out_len = 0; return (unsigned char*)strdup(""); }
    uint32_t pwd[2048] = {0}; int pwd_len = 0;
    sencode(msg, strlen(msg), pwd, &pwd_len, 1);
    uint32_t pwdk[2048] = {0}; int pwdk_len = 0;
    sencode(key, strlen(key), pwdk, &pwdk_len, 0);
    if (pwdk_len < 4) { for (int i = pwdk_len; i < 4; i++) pwdk[i] = 0; pwdk_len = 4; }
    int n = pwd_len - 1;
    uint32_t z = pwd[n], y = pwd[0], c = 0x86014019 | 0x183639A0, m, e, p;
    int q = 6 + 52 / (n + 1); uint32_t d = 0;
    while (q > 0) {
        d = (d + c) & 0xffffffff; e = (d >> 2) & 3;
        for (p = 0; p < n; p++) {
            y = pwd[p + 1];
            m = (z >> 5 ^ y << 2) + ((y >> 3 ^ z << 4) ^ (d ^ y)) + (pwdk[(p & 3) ^ e] ^ z);
            pwd[p] = (pwd[p] + m) & 0xffffffff; z = pwd[p];
        }
        y = pwd[0];
        m = (z >> 5 ^ y << 2) + ((y >> 3 ^ z << 4) ^ (d ^ y)) + (pwdk[(p & 3) ^ e] ^ z);
        pwd[n] = (pwd[n] + m) & 0xffffffff; z = pwd[n]; q--;
    }
    return lencode(pwd, pwd_len, 0, out_len);
}

// ==========================================
// 5. Main Execution
// ==========================================
int main(int argc, char *argv[]) {
    if (argc != 9) {
        printf("Usage: %s <user> <pass> <ip> <acid> <enc_ver> <token> <n> <type>\n", argv[0]);
        return 1;
    }
    char *username = argv[1], *password = argv[2], *ip = argv[3], *acid = argv[4];
    char *enc_ver = argv[5], *token = argv[6], *n = argv[7], *type = argv[8];

    // 1. Generate MD5 (HMAC)
    unsigned char md5_raw[16];
    hmac_md5((unsigned char*)token, strlen(token), (unsigned char*)password, strlen(password), md5_raw);
    char md5_hex[33];
    for (int i = 0; i < 16; i++) sprintf(md5_hex + (i * 2), "%02x", md5_raw[i]);

    // 2. Generate Info
    char info_json[512];
    sprintf(info_json, "{\"username\":\"%s\",\"password\":\"%s\",\"ip\":\"%s\",\"acid\":\"%s\",\"enc_ver\":\"%s\"}",
            username, password, ip, acid, enc_ver);
    int xenc_len = 0;
    unsigned char *xenc_out = get_xencode(info_json, token, &xenc_len);
    char *base64_info = get_base64(xenc_out, xenc_len);
    char encrypted_info[1024];
    sprintf(encrypted_info, "{SRBX1}%s", base64_info);

    // 3. Generate Checksum (SHA1)
    char chkstr[2048];
    sprintf(chkstr, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
            token, username, token, md5_hex, token, acid, token, ip, token, n, token, type, token, encrypted_info);
    char sha1_hex[41];
    get_sha1(chkstr, sha1_hex);

    // Output strictly in 3 lines for shell script parsing
    printf("{MD5}%s\n", md5_hex);
    printf("%s\n", encrypted_info);
    printf("%s\n", sha1_hex);

    free(xenc_out); free(base64_info);
    return 0;
}
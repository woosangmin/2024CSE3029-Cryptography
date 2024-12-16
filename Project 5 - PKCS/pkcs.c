/*
 * Copyright(c) 2020-2024 All rights reserved by Heekuck Oh.
 * 이 프로그램은 한양대학교 ERICA 컴퓨터학부 학생을 위한 교육용으로 제작되었다.
 * 한양대학교 ERICA 학생이 아닌 자는 이 프로그램을 수정하거나 배포할 수 없다.
 * 프로그램을 수정할 경우 날짜, 학과, 학번, 이름, 수정 내용을 기록한다.
 */

/* By the grace of the Lord */

#ifdef __linux__
#include <bsd/stdlib.h>
#elif __APPLE__
#include <stdlib.h>
#else
#include <stdlib.h>
#endif
#include <string.h>
#include <stdint.h>
#include <gmp.h>
#include "pkcs.h"
#include "sha2.h"

// 해시 함수가 처리할 수 있는 message digest 크기(모음), count용 i, 반환값
int hLen, i, result;
const int hash_output[6] = {SHA224_DIGEST_SIZE, SHA256_DIGEST_SIZE, SHA384_DIGEST_SIZE, SHA512_DIGEST_SIZE, SHA224_DIGEST_SIZE, SHA256_DIGEST_SIZE};

// padding string과 메시지를 분리하기 위한 0x01 / 암호문을 수치화한 값이 key보다 작도록 하는 0x00 / 서명문의 맨 뒤에 붙이는 0xbc
const unsigned char line[1] = {0x01}, small[1] = {0x00}, bc[1] = {0xbc};

// 서명 생성, 검증 시 M'[(0x)00 00 00 00 00 00 00 00 || mHash || salt]을 생성하기 위해 필요한 변수
const unsigned char empty[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/* check_length() - label의 길이가 사용자가 선택한 해시 함수가 
   처리할 수 있는 메시지의 최대 길이보다 긴지 비교하는 함수 
*/
int check_length(size_t l_length, int sha_index) {
    // 이상 없을 시 반환할 결과값
    result = 0;
    // 메시지의 길이를 담을 변수를 초기화한다.
    mpz_t n_length;
    // 해시 함수가 최대로 지원하는 message 크기를 담을 변수를 초기화한다.
    mpz_t small_bound, large_bound;
    mpz_inits(small_bound, large_bound, n_length, NULL);
    // SHA224/256은 최대 2^64 - 1 bit의 메시지를 처리할 수 있다.
    mpz_set_str(small_bound, "1FFFFFFFFFFFFFFF", 16);
    // SHA384 이상은 최대 2^128 - 1 bit의 메시지를 처리할 수 있다.
    mpz_set_str(large_bound, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);

    // n_length에 메시지의 길이를 복사한다.
    mpz_set_ui(n_length, l_length);

    // 메시지의 길이가 small_bound나 large_bound를 넘었는지 비교한다.
    if (sha_index < SHA384) {
        if (mpz_cmp(n_length, small_bound) > 0) result = PKCS_LABEL_TOO_LONG;
        else result = 0;
    } else {
        if (mpz_cmp(n_length, large_bound) > 0) result = PKCS_LABEL_TOO_LONG;
        else result = 0;
    }
    // mpz 변수가 사용한 메모리를 초기화한다.
    mpz_clears(small_bound, large_bound, n_length, NULL);

    return result;
}

/* calc_hash() - 사용자가 지정한 hash 함수를 이용하여 HASH(L)을 계산하는 함수
   sha224/256/384/512/512_224/512_256을 지원한다.
*/
void calc_hash(void *label, size_t length, void *digest, int sha2_idx) {
    // label을 사용자가 지정한 해시 함수로 처리하여 hash에 저장한다.
    if (sha2_idx == SHA224) {
        sha224(label, length, digest);
    } else if (sha2_idx == SHA256) {
        sha256(label, length, digest);
    } else if (sha2_idx == SHA384) {
        sha384(label, length, digest);
    } else if (sha2_idx == SHA512) {
        sha512(label, length, digest);
    } else if (sha2_idx == SHA512_224) {
        sha512_224(label, length, digest);
    } else if (sha2_idx == SHA512_256) {
        sha512_256(label, length, digest);
    }
}

/* mgf1() - Mask Generation Functions
   src 배열을 해시 함수로 처리한 결과를 앞에서부터
   target의 길이만큼 잘라내어 복사하는 함수
*/
int mgf1(void *src, size_t src_length, void *target, size_t maskLen, int sha2_ndx) {

    // 한 종류의 해시 함수만 사용하는 것이 아니라 사용자가 지정한 해시 함수를 사용해야한다.
    // 따라서 hLen(사용자가 지정한 해시 함수가 처리할 수 있는 message digest 크기)이 필요하다.
    // 반환할 결과값
    result = 0;

    // maskLen이 2^32 * hLen보다 클 경우 에러메시지를 반환한다.
    if (maskLen > ((uint64_t)hLen << 32)) result = PKCS_MASK_TOO_LONG;

    // mask를 몇 번째 생성 중인지 계산하는 변수
    size_t count = 0;
    // count를 4바이트 string으로 변환한 결과를 담을 변수
    unsigned char counter[4] ={0x00, 0x00, 0x00, 0x00};
    // src + counter를 저장할 변수와 src + counter를 해시함수로 처리한 결과를 담을 변수
    int temp_length = src_length + 4; unsigned char temp[src_length + 4], hash[hLen];
    // 해시함수로 처리한 결과를 누적해서 담을 변수
    unsigned char output[((maskLen + hLen) / hLen + 1) * hLen];
    // count가 ((maskLen + hLen - 1) / hLen) - 1에 도달할 때까지 반복한다.
    int limit = ((maskLen + hLen - 1) / hLen) - 1;
    while (count <= limit) {
        // count를 4바이트 string으로 변환한 결과를 counter에 저장한다.
        // big-endian으로 저장해야한다.
        counter[3] = (count) & 0xFF;
        counter[2] = (count >> 8) & 0xFF;
        counter[1] = (count >> 16) & 0xFF;
        counter[0] = (count >> 24) & 0xFF;
        // temp에 src와 counter를 순차적으로 저장한다.
        memcpy(temp, src, src_length);
        memcpy(temp + src_length, counter, 4);

        // temp를 해시 처리하고 결과를 hash에 저장한다.
        calc_hash(temp, temp_length, hash, sha2_ndx);

        // hash에 저장된 결과를 output에 누적하여 저장한다.
        memcpy(output + (count * hLen), hash, hLen);

        count++;
    }
    // 최종적으로 output의 앞에서부터 maskLen까지의 string을 잘라내어 target에 저장한다.
    memcpy(target, output, maskLen);

    return result;
}

/*
 * rsa_generate_key() - generates RSA keys e, d and n in octet strings.
 * If mode = 0, then e = 65537 is used. Otherwise e will be randomly selected.
 * Carmichael's totient function Lambda(n) is used.
 */
void rsa_generate_key(void *_e, void *_d, void *_n, int mode)
{
    mpz_t p, q, p_1, q_1, lambda, e, d, n, gcd;
    gmp_randstate_t state;
    
    /*
     * Initialize mpz variables
     */
    mpz_inits(p, q, p_1, q_1, lambda, e, d, n, gcd, NULL);
    gmp_randinit_default(state);
    gmp_randseed_ui(state, arc4random());
    /*
     * Generate prime p and q such that 2^(RSAKEYSIZE-1) <= p*q < 2^RSAKEYSIZE
     * (p-1) and (q-1) are relatively prime to 2^16+1 (65537).
     */
    do {
        /*
         * Select a random prime p, where (p-1) is relatively prime to 65537.
         */
        do {
            do {
                mpz_urandomb(p, state, RSAKEYSIZE/2);
                mpz_setbit(p, 0);
                mpz_setbit(p, RSAKEYSIZE/2-1);
            } while (mpz_probab_prime_p(p, 50) == 0);
            mpz_sub_ui(p_1, p, 1);
        } while (mpz_gcd_ui(gcd, p_1, 65537) != 1);
        /*
         * Select a random prime q, where (q-1) is relatively prime to 65537.
         */
        do {
            do {
                mpz_urandomb(q, state, RSAKEYSIZE/2);
                mpz_setbit(q, 0);
                mpz_setbit(q, RSAKEYSIZE/2-1);
            } while (mpz_probab_prime_p(q, 50) == 0);
            mpz_sub_ui(q_1, q, 1);
        } while (mpz_gcd_ui(gcd, q_1, 65537) != 1);
        /*
         * Compute n = p * q
         */
        mpz_mul(n, p, q);
    } while (!mpz_tstbit(n, RSAKEYSIZE-1));
    /*
     * Generate e and d using Lambda(n)
     */
    mpz_lcm(lambda, p_1, q_1);
    if (mode == 0)
        mpz_set_ui(e, 65537);
    else do {
        mpz_urandomb(e, state, RSAKEYSIZE);
        mpz_gcd(gcd, e, lambda);
    } while (mpz_cmp(e, lambda) >= 0 || mpz_cmp_ui(gcd, 1) != 0);
    mpz_invert(d, e, lambda);
    /*
     * Convert mpz_t values into octet strings
     */
    mpz_export(_e, NULL, 1, RSAKEYSIZE/8, 1, 0, e);
    mpz_export(_d, NULL, 1, RSAKEYSIZE/8, 1, 0, d);
    mpz_export(_n, NULL, 1, RSAKEYSIZE/8, 1, 0, n);
    /*
     * Free the space occupied by mpz variables
     */
    mpz_clears(p, q, p_1, q_1, lambda, e, d, n, gcd, NULL);
}

/*
 * rsa_cipher() - compute m^k mod n
 * If m >= n then returns PKCS_MSG_OUT_OF_RANGE, otherwise returns 0 for success.
 */
static int rsa_cipher(void *_m, const void *_k, const void *_n)
{
    mpz_t m, k, n;
    
    /*
     * Initialize mpz variables
     */
    mpz_inits(m, k, n, NULL);
    /*
     * Convert big-endian octets into mpz_t values
     */
    mpz_import(m, RSAKEYSIZE/8, 1, 1, 1, 0, _m);
    mpz_import(k, RSAKEYSIZE/8, 1, 1, 1, 0, _k);
    mpz_import(n, RSAKEYSIZE/8, 1, 1, 1, 0, _n);
    /*
     * Compute m^k mod n
     */
    if (mpz_cmp(m, n) >= 0) {
        mpz_clears(m, k, n, NULL);
        return PKCS_MSG_OUT_OF_RANGE;
    }
    mpz_powm(m, m, k, n);
    /*
     * Convert mpz_t m into the octet string _m
     */
    mpz_export(_m, NULL, 1, RSAKEYSIZE/8, 1, 0, m);
    /*
     * Free the space occupied by mpz variables
     */
    mpz_clears(m, k, n, NULL);
    return 0;
}

/*
 * rsaes_oaep_encrypt() - RSA encrytion with the EME-OAEP encoding method
 * 길이가 len 바이트인 메시지 m을 공개키 (e,n)으로 암호화한 결과를 c에 저장한다.
 * label은 데이터를 식별하기 위한 라벨 문자열로 NULL을 입력하여 생략할 수 있다.
 * sha2_ndx는 사용할 SHA-2 해시함수 색인 값으로 SHA224, SHA256, SHA384, SHA512,
 * SHA512_224, SHA512_256 중에서 선택한다. c의 크기는 RSAKEYSIZE와 같아야 한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int rsaes_oaep_encrypt(const void *m, size_t mLen, const void *label, const void *e, const void *n, void *c, int sha2_ndx)
{
    // 반환할 결과값
    result = 0;
    // Length Checking
    // label의 길이(바이트)를 구한다.
    size_t label_len = strlen((char *)label); 
    // 반환할 결과값
    result = 0;

    // label의 길이가 0이 아닌 경우 해시 함수로 처리 가능한지 확인한다.
    if (label_len != 0 && check_length(label_len, sha2_ndx)) return PKCS_LABEL_TOO_LONG;

    // hLen(사용자가 지정한 해시 함수가 처리할 수 있는 message digest 크기)을 생성한다.
    hLen = hash_output[sha2_ndx];

    // 만약 메시지의 길이가 kLen - 2 * hLen - 2보다 길면 오류 메시지를 반환한다.
    if (mLen > KLEN - 2 * hLen - 2) return PKCS_MSG_TOO_LONG;

    // 사용자가 지정한 hash 함수를 이용하여 HASH(L)을 계산한다.
    unsigned char hash_l[hLen];
    calc_hash((void *)label, label_len, &hash_l, sha2_ndx);

    // DataBlock을 생성한다.
    // DataBlock의 길이는 kLen - hLen - 1이다.
    int db_length = KLEN - hLen - 1; unsigned char DB[db_length]; 
    // padding string의 길이를 계산한다.
    int padding_len = KLEN - mLen - 2 * hLen - 2;

    if (padding_len > 0) {
        // padding string이 필요한 경우 padding string을 생성하고 
        // HASH(L) + padding string + 0x01 + message 순으로 이어 붙여 DataBlock을 생성한다.
        unsigned char padding[padding_len];
        memset(padding, 0, padding_len);
        memcpy(DB, hash_l, hLen);
        memcpy(DB + hLen, padding, padding_len);
        memcpy(DB + hLen + padding_len, line, 1);
        memcpy(DB + hLen + padding_len + 1, m, mLen);
    } else {
        // padding string이 필요하지 않은 경우 HASH(L) + 0x01 + message 순으로 이어 붙여 DataBlock을 생성한다.
        memcpy(DB, hash_l, hLen);
        memcpy(DB + hLen, line, 1);
        memcpy(DB + hLen + 1, m, mLen);
    }

    // hLen 길이의 random seed를 생성한다.
    unsigned char seed[hLen];
    arc4random_buf(&seed, sizeof(seed));

    // seed를 mgf1으로 처리한 결과를 dbMask에 저장한다.
    unsigned char dbMask[db_length];
    result = mgf1(&seed, hLen, &dbMask, db_length, sha2_ndx);
    // 에러 발생 시 에러 메시지를 반환한다.
    if (result) return result;

    // dbMask와 DB를 XOR하여 maskedDB를 생성한다.
    unsigned char maskedDB[db_length];
    for (i = 0 ; i < db_length / 4 ; i++) {
        ((uint32_t *)maskedDB)[i] = ((uint32_t *)dbMask)[i] ^ ((uint32_t *)DB)[i];
    }

    for (i = db_length / 4 * 4 ; i < db_length ; i++) {
        maskedDB[i] = dbMask[i] ^ DB[i];
    }   

    // maskedDB를 mgf1으로 처리한 결과를 seedMask에 저장한다.
    unsigned char seedMask[hLen];
    result = mgf1(&maskedDB, db_length, &seedMask, hLen, sha2_ndx);
    // 에러 발생 시 에러 메시지를 반환한다.
    if (result) return result;

    // seedMask와 seed를 XOR하여 maskedSeed를 생성한다.
    unsigned char maskedSeed[hLen];
    for (i = 0 ; i < hLen / 4 ; i++) {
        ((uint32_t *)maskedSeed)[i] = ((uint32_t *)seedMask)[i] ^ ((uint32_t *)seed)[i];
    }

    // Encoded Message를 생성한다. EM = 0x00 || maskedSeed || maskedDB
    memcpy(c, small, 1);
    memcpy(c + 1, maskedSeed, hLen);
    memcpy(c + 1 + hLen, maskedDB, KLEN - hLen - 1);

    // Encoded message를 공개키를 활용하여 암호화 한다.
    result = rsa_cipher(c, e, n);

    // 성공 여부를 반환한다.
    return result;
}

/*
 * rsaes_oaep_decrypt() - RSA decrytion with the EME-OAEP encoding method
 * 암호문 c를 개인키 (d,n)을 사용하여 원본 메시지 m과 길이 len을 회복한다.
 * label과 sha2_ndx는 암호화할 때 사용한 것과 일치해야 한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int rsaes_oaep_decrypt(void *m, size_t *mLen, const void *label, const void *d, const void *n, const void *c, int sha2_ndx)
{
    // 반환할 결과값
    result = 0;
    // Length Checking
    // label의 길이(바이트)를 구한다.
    size_t label_len = strlen((char *)label); 

    // label의 길이가 0이 아닌 경우 해시 함수로 처리 가능한지 확인한다.
    if (label_len != 0 && check_length(label_len, sha2_ndx)) return PKCS_LABEL_TOO_LONG;

    // hLen(사용자가 지정한 해시 함수가 처리할 수 있는 message digest 크기)을 생성한다.
    hLen = hash_output[sha2_ndx];

    // 키의 길이가 2 * hLen + 2보다 작은 경우 오류 메시지를 반환한다.
    if (KLEN < 2 * hLen + 2) return DECRYPTION_ERROR;

    // Encoded message를 담을 변수
    static unsigned char EM[KLEN];

    // c가 const void 형이므로 암호문의 내용을 Encoded message에 복사한다.
    memcpy(EM, c, KLEN);

    // 암호문을 복호화하고 오류가 발생했으면 오류 메시지를 반환한다.
    result = rsa_cipher((void *)EM, d, n);
    if (result) return result;

    // 만약 Encoded message의 첫 번째 바이트가 0x00이 아니면 오류 메시지를 반환한다.
    if (EM[0] != 0x00) return PKCS_INITIAL_NONZERO;

    // Encoded message에서 maskedSeed, maskedDB를 순차적으로 분리한다.
    int db_length = KLEN - hLen - 1;
    unsigned char maskedSeed[hLen], maskedDB[db_length];
    memcpy(maskedSeed, EM + 1, hLen);
    memcpy(maskedDB, EM + 1 + hLen, db_length);

    // maskedDB를 mgf1로 처리한 결과를 seedMask에 저장한다.
    unsigned char seedMask[hLen];
    result = mgf1(&maskedDB, db_length, &seedMask, hLen, sha2_ndx);
    // 에러 발생 시 에러 메시지를 반환한다.
    if (result) return result;

    // seedMask와 maskedSeed를 XOR하여 seed를 복원한다.
    unsigned char seed[hLen];
    for (i = 0 ; i < hLen / 4 ; i++) {
        ((uint32_t *)seed)[i] = ((uint32_t *)seedMask)[i] ^ ((uint32_t *)maskedSeed)[i];
    }

    // seed를 mgf1으로 처리한 결과를 dbMask에 저장한다.
    unsigned char dbMask[db_length];
    result = mgf1(&seed, hLen, &dbMask, db_length, sha2_ndx);
    // 에러 발생 시 에러 메시지를 반환한다.
    if (result) return result;

    // maskedDB와 dbMask를 XOR하여 DB에 저장한다.
    unsigned char DB[db_length];
    for (i = 0 ; i < db_length / 4 ; i++) {
        ((uint32_t *)DB)[i] = ((uint32_t *)maskedDB)[i] ^ ((uint32_t *)dbMask)[i];
    }

    for (i = db_length / 4 * 4 ; i < db_length ; i++) {
        DB[i] = maskedDB[i] ^ dbMask[i];
    }

    // 검증용 Hash(L)을 생성한다.
    unsigned char hash_l[hLen];
    calc_hash((void *)label, label_len, &hash_l, sha2_ndx);

    // DB에서 Hash(L)을 분리한다.
    unsigned char n_hash_l[hLen];
    memcpy(n_hash_l, DB, hLen);

    // 만약 복원된 Hash(L)과 검증용 Hash(L)이 서로 다르면 오류 메시지를 반환한다.
    if (memcmp(n_hash_l, hash_l, hLen)) return PKCS_HASH_MISMATCH;

    // padding string이 존재하는지 확인한다.
    int ps_len = 0;
    // DB에서 Hash(L)을 제외한 나머지 블록들을 읽어서 0x01의 위치를 확인한다.
    int *indicate = memchr(DB + hLen, 0x01, db_length);
    // NULL인 경우 에러메시지를 반환하고 아닌 경우 padding string의 길이를 계산한다.
    if (indicate != NULL) ps_len = (int)((intptr_t)indicate - (intptr_t)(DB + hLen)); // intptr_t  : an integer type allowing it to store pointer addresses without loss of information. / <stdint.h>
    else return PKCS_INVALID_PS;

    if (ps_len == 0) {
        // padding string이 존재하지 않으면 db에서 hash(L)을 제외하고 남은
        // 나머지 string의 맨 처음 바이트가 0x01인지 확인한다. 아닌 경우 오류메시지를 반환한다.
        if (DB[hLen] != 0x01) return PKCS_INVALID_PS;
        // padding string이 존재하지 않기 때문에 메시지의 길이는 kLen - 2*hLen - 2이다.
        *mLen = KLEN - 2*hLen - 2;
        // DB에서 메시지의 길이만큼 m에 데이터를 복사한다. 
        memcpy(m, DB + hLen + 1, *mLen);
    } else {
        // padding string이 존재하면 db에 존재하는 padding string이 0x00인지 확인하고
        // 아닌 경우 오류 메시지를 반환한다.
        unsigned char *buf = calloc(1, ps_len); // malloc(ps_len); memset(ptr, 0, ps_len);
        if (memcmp(DB + hLen, buf, ps_len)) {
            free(buf);
            return PKCS_INVALID_PS; }
        // 만약 오류가 발생하지 않았으면 buf를 release한다.
        free(buf);
        // padding string이 존재하면 db에서 hash(L)과 padding string을 제외하고 남은
        // 나머지 string의 맨 처음 바이트가 0x01인지 확인한다. 아닌 경우 오류메시지를 반환한다.
        if (DB[hLen + ps_len] != 0x01) return PKCS_INVALID_PS;
        // padding string이 존재하기 때문에 메시지의 길이는 kLen - 2*hLen - ps_len - 2이다.
        *mLen = KLEN - 2*hLen - ps_len - 2;
        // DB에서 메시지의 길이만큼 m에 데이터를 복사한다. 
        memcpy(m, DB + hLen + ps_len + 1, *mLen);
    }
    
    // EM은 static 변수이므로 모든 복호화 작업을 마치고 0으로 초기화한다.
    memset(EM, 0, KLEN);

    // 정상적으로 복호화되었으므로 0을 반환한다.
    return result;
}

/*
 * rsassa_pss_sign - RSA Signature Scheme with Appendix
 * 길이가 len 바이트인 메시지 m을 개인키 (d,n)으로 서명한 결과를 s에 저장한다.
 * s의 크기는 RSAKEYSIZE와 같아야 한다. 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int rsassa_pss_sign(const void *m, size_t mLen, const void *d, const void *n, void *s, int sha2_ndx)
{
    // 반환할 결과값
    result = 0;
    // Length Checking
    // message가 해시 함수로 처리 가능한지 확인한다.
    if (check_length(mLen, sha2_ndx)) return PKCS_MSG_TOO_LONG;

    // hLen(사용자가 지정한 해시 함수가 처리할 수 있는 message digest 크기)을 생성한다.
    hLen = hash_output[sha2_ndx];

    // mHash를 생성한다.
    unsigned char mHash[hLen];
    calc_hash((void *)m, mLen, &mHash, sha2_ndx);

    // emLen이 hLen + sLen + 2보다 작을 경우 에러메시지를 반환한다(salt의 길이는 hLen이다).
    if (EMLEN < 2 * hLen + 2) return PKCS_HASH_TOO_LONG;

    // salt를 생성한다.
    unsigned char salt[hLen];
    arc4random_buf(&salt, sizeof(salt));

    // hashed_m을 생성한다. 
    int hm_length = 8 + 2 * hLen; 
    unsigned char hashed_m[hm_length];
    memcpy(hashed_m, empty, 8);
    memcpy(hashed_m + 8, mHash, hLen);
    memcpy(hashed_m + 8 + hLen, salt, hLen);

    // hashed_m2를 생성한다.
    unsigned char hashed_m2[hLen];
    calc_hash(&hashed_m, hm_length, &hashed_m2, sha2_ndx);

    // DataBlock을 생성한다. DB = PS || 0x01 || salt
    int db_length = EMLEN - hLen - 1, ps_len = EMLEN - 2 * hLen - 2; unsigned char DB[db_length]; 
    // 필요한 경우 DataBlock 앞에 padding string을 붙인다.
    memset(DB, 0, ps_len);
    // 이어서 0x01, salt를 차례로 더한다.
    memcpy(DB + ps_len, line, 1);
    memcpy(DB + ps_len + 1, salt, hLen);

    // dbMask를 생성한다.
    unsigned char dbMask[db_length];
    result = mgf1(&hashed_m2, hLen, &dbMask, db_length, sha2_ndx);
    // 에러 발생 시 에러 메시지를 반환한다.
    if (result) return result;

    // maskedDB를 생성한다.
    unsigned char maskedDB[db_length];
    for (i = 0 ; i < db_length / 4 ; i++) {
        ((uint32_t *)maskedDB)[i] = ((uint32_t *)DB)[i] ^ ((uint32_t *)dbMask)[i];
    }
    for (i = db_length / 4 * 4 ; i < db_length ; i++) {
        maskedDB[i] = DB[i] ^ dbMask[i];
    }

    // maskedDB의 맨 왼쪽 1비트를 0으로 설정한다.
    maskedDB[0] = maskedDB[0] & 0b01111111;

    // Encoded message를 생성한다. EM = maskedDB || hashed_m2 || 0xbc
    memcpy(s, maskedDB, db_length);
    memcpy(s + db_length, hashed_m2, hLen);
    memcpy(s + EMLEN - 1, bc, 1);

    // 개인키로 서명한다.
    result = rsa_cipher(s, d, n);

    // 결과 값을 반환한다.
    return result;
}

/*
 * rsassa_pss_verify - RSA Signature Scheme with Appendix
 * 길이가 len 바이트인 메시지 m에 대한 서명이 s가 맞는지 공개키 (e,n)으로 검증한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int rsassa_pss_verify(const void *m, size_t mLen, const void *e, const void *n, const void *s, int sha2_ndx)
{
    // 반환할 결과값
    result = 0;
    // Length Checking
    // message가 해시 함수로 처리 가능한지 확인한다.
    if (check_length(mLen, sha2_ndx)) return PKCS_MSG_TOO_LONG;

    // hLen(사용자가 지정한 해시 함수가 처리할 수 있는 message digest 크기)을 생성하고 키의 바이트 길이를 emLen에 저장한다.
    hLen = hash_output[sha2_ndx];

    // emLen이 2 * hLen + 2보다 작은 경우 오류 메시지를 반환한다(salt의 길이는 hLen이다).
    if (EMLEN < 2 * hLen + 2) return VERIFICATION_ERROR;

    // Encoded message를 담을 변수
    static unsigned char EM[KLEN];

    // 서명의 내용을 EM에 복사한다.
    memcpy(EM, s, EMLEN);

    // 서명을 복호화하고 오류가 발생했으면 오류 메시지를 반환한다.
    result = rsa_cipher((void *)EM, e, n);
    if (result != 0) return result;

    // 만약 EM의 맨 오른쪽 바이트가 0xbc가 아닌 경우 오류 메시지를 반환한다.
    if (EM[EMLEN-1] != 0xbc) return PKCS_INVALID_LAST;

    // maskedDB를 EM에서 분리한다.
    int db_length = EMLEN - hLen - 1; 
    unsigned char maskedDB[db_length], hashed_m2[hLen];
    memcpy(maskedDB, EM, db_length);

    // 만약 EM의 처음 비트가 0이 아니면 오류 메시지를 반환한다.
    if ((maskedDB[0] >> 7) != 0b0) return PKCS_INVALID_INIT;

    // hashed_m2를 EM에서 분리한다
    memcpy(hashed_m2, EM + db_length, hLen);

    // dbMask를 생성한다.
    unsigned char dbMask[db_length];
    result = mgf1(&hashed_m2, hLen, &dbMask, db_length, sha2_ndx);
    // 에러 발생 시 에러 메시지를 반환한다.
    if (result) return result;

    // DB를 복원한다.
    unsigned char DB[db_length];
    for (i = 0 ; i < db_length / 4 ; i++) {
        ((uint32_t *)DB)[i] = ((uint32_t *)maskedDB)[i] ^ ((uint32_t *)dbMask)[i];
    }
    for (i = db_length / 4 * 4 ; i < db_length ; i++) {
        DB[i] = maskedDB[i] ^ dbMask[i];
    }

    // DB의 맨 왼쪽 비트를 0으로 바꾼다.
    DB[0] = DB[0] & 0b01111111;

    // DB에서 padding string이 존재하는지 확인한다.
    int ps_len = EMLEN - 2 * hLen - 2;
    // padding string이 존재하면 내용이 0x00인지 확인한다.
    unsigned char *buf = calloc(1, ps_len);
    // 만약 padding string이 0x00이 아니라면 오류 메시지를 반환한다. 
    // memcmp는 차이가 있을 경우 0이 아닌 수를 반환한다.
    if (memcmp(DB, buf, ps_len)) {
        free(buf);
        return PKCS_INVALID_PD2;}
    // 만약 오류가 발생하지 않았으면 buf를 release한다.
    free(buf);
    // DB[ps_len]가 0x01인지 확인한다.
    if (DB[ps_len] != 0x01) return PKCS_INVALID_PD2;

    // salt를 복원한다.
    unsigned char salt[hLen];
    memcpy(salt, DB + EMLEN - 2 * hLen - 1, hLen);

    // 서명을 검증하기 위해 mhash를 생성한다.
    unsigned char mhash[hLen];
    calc_hash((void *)m, mLen, &mhash, sha2_ndx);

    // 검증용 메시지를 생성한다.
    int hm_length = 8 + 2 * hLen;
    unsigned char hashed_m[hm_length]; 
    unsigned char ver_m[hLen];
    memcpy(hashed_m, empty, 8);
    memcpy(hashed_m + 8, mhash, hLen);
    memcpy(hashed_m + 8 + hLen, salt, hLen);
    calc_hash(&hashed_m, hm_length, &ver_m, sha2_ndx);

    // 검증용 메시지와 복원된 메시지가 다르면 오류 메시지를 반환한다.
    if (memcmp(ver_m, hashed_m2, hLen)) return PKCS_HASH_MISMATCH;

    // EM은 static 변수이므로 모든 복호화 작업을 마치고 0으로 초기화한다.
    memset(EM, 0, KLEN);

    return result;
}

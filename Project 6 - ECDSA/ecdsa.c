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
#include "ecdsa.h"
#include "sha2.h"
#include <gmp.h>
#include <string.h>

// 시스템 파라미터
mpz_t p, n, a;
ecdsa_p256_t G;
const unsigned char Gx[ECDSA_P256/8] = {0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96};
const unsigned char Gy[ECDSA_P256/8] = {0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5};

// 해시 함수가 처리할 수 있는 message digest 크기(모음)
int hLen; const int hash_output[6] = {SHA224_DIGEST_SIZE, SHA256_DIGEST_SIZE, SHA384_DIGEST_SIZE, SHA512_DIGEST_SIZE, SHA224_DIGEST_SIZE, SHA256_DIGEST_SIZE};

/*
 * Initialize 256 bit ECDSA parameters
 * 시스템파라미터 p, n, a, G의 공간을 할당하고 값을 초기화한다.
 */
void ecdsa_p256_init(void)
{
    // G를 초기화한다.
    memcpy(G.x, Gx, ECDSA_P256/8);
    memcpy(G.y, Gy, ECDSA_P256/8);

    // p, n, a를 초기화한다.
    mpz_inits(p, n, a, NULL);

    mpz_set_ui(a, 3);

    mpz_set_str(p, "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);

    mpz_set_str(n, "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);

}

/*
 * Clear 256 bit ECDSA parameters
 * 할당된 파라미터 공간을 반납한다.
 */
void ecdsa_p256_clear(void)
{
    // p, n, a를 초기화한다.
    mpz_clears(p, n, a, NULL);
}

/* check_length() - label의 길이가 사용자가 선택한 해시 함수가 
   처리할 수 있는 메시지의 최대 길이보다 긴지 비교하는 함수 
*/
int check_length(size_t l_length, int sha_index) {
    // 이상 없을 시 반환할 결과값
    int result = 0;
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
        if (mpz_cmp(n_length, small_bound) > 0) result = ECDSA_MSG_TOO_LONG;
        else result = 0;
    } else {
        if (mpz_cmp(n_length, large_bound) > 0) result = ECDSA_MSG_TOO_LONG;
        else result = 0;
    }
    // mpz 변수가 사용한 메모리를 초기화한다.
    mpz_clears(small_bound, large_bound, n_length, NULL);

    return result;
}

/* calc_hash() - 사용자가 지정한 hash 함수를 이용하여 HASH(L)을 계산하는 함수
   sha224/256/384/512/512_224/512_256을 지원한다.
*/
void calc_hash(const void *label, size_t length, void *digest, int sha2_idx) {
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

/*
* bit2int - convert a bit string to an Integer mod n 
*           via Modular reduction
*/
int bit2int(mpz_t x) {

    // bit string을 정수로 변환하기 위해 필요한 변수들을 초기화한다.
    mpz_t N, r, rho, epslion, n_1, left, right, temp;
    mpz_inits(N, r, rho, epslion, n_1, left, right, temp, NULL);

    // x의 비트 길이를 확인한다.
    size_t l = mpz_sizeinbase(x, 2);

    // N에 2^l을 저장한다.
    mpz_ui_pow_ui(N, 2, l);

    // 만약 n이 N보다 크다면 ERROR를 반환한다.
    if (mpz_cmp(n, N) > 0) {
        mpz_clears(N, r, rho, epslion, n_1, left, right, temp, NULL);
        return ERROR;
    }

    // epsilon(the upper bound on bias)에 2^(-64)을 저장한다.
    mpz_set_ui(epslion, 1);
    mpz_div_2exp(epslion, epslion, 64);

    // n_1에 n-1을 저장한다.
    mpz_sub_ui(n_1, n, 1);

    // r에 N mod (n-1)을 저장한다.
    mpz_mod(r, N, n_1);

    // rho에 r / n-1을 저장한다.
    mpz_tdiv_q(rho, r, n_1);

    // left 계산
    mpz_mul_ui(left, rho, 2);
    mpz_set_ui(temp, 1);
    mpz_sub(temp, temp, rho);
    mpz_mul(left, left, temp);
    mpz_mul(left, left, n_1);

    // right 계산
    mpz_mul(right, epslion, N);

    // 만약 2 * rho * (1 - rho) * (n - 1)이 epslion * N보다 크면 ERROR를 반환한다.
    if (mpz_cmp(left, right) > 0) {
        mpz_clears(N, r, rho, epslion, n_1, left, right, temp, NULL);
        return ERROR;
    }
    // x mod n-1을 x에 저장한다.
    mpz_mod(x, x, n_1);

    // x + 1을 x에 저장한다.
    mpz_add_ui(x, x, 1);

    // 만약 계산된 x의 MSB가 1이 아니라면 n의 비트 길이와 맞추기 위해 MSB를 1로 설정한다. 
    // x의 범위는 1 ~ n-1, MSB를 1로 바꿔도 n을 넘지 않는다. 
    if (mpz_tstbit(x, ECDSA_P256-1) == 0) mpz_setbit(x, ECDSA_P256-1);

    // mpz_t 변수들을 초기화한다.
    mpz_clears(N, r, rho, epslion, n_1, left, right, temp, NULL);

    // 성공하였으므로 0을 리턴한다.
    return 0;
}

/*
* mod_add - perform modular addition
* (x + y) mod dvs를 계산한다.
 */
void mod_add(mpz_t result, mpz_t x, mpz_t y, mpz_t dvs) {
    // 계산결과를 일시적으로 담을 변수 temp를 생성한다.
    mpz_t temp, nx, ny;
    mpz_inits(temp, nx, ny, NULL);
    // x mod dvs과 y mod dvs를 각각 계산한다.
    mpz_mod(nx, x, dvs);
    mpz_mod(ny, y, dvs);
    // temp에 x + y를 저장한다.
    mpz_add(temp, nx, ny);
    // temp가 dvs보다 크거나 같으면 result에 temp - dvs를 저장한다.
    if (mpz_cmp(temp, dvs) >= 0) mpz_sub(result, temp, dvs);
    else mpz_set(result, temp); // temp의 값을 result에 저장한다.
    // 사용을 완료한 변수를 초기화한다.
    mpz_clears(temp, nx, ny, NULL);
}

/*
* mod_sub - perform modular subtraction
* (x - y) mod dvs를 계산한다.
 */
void mod_sub(mpz_t result, mpz_t x, mpz_t y, mpz_t dvs) {
    // 계산결과를 일시적으로 담을 변수 temp를 생성한다.
    mpz_t temp, nx, ny;
    mpz_inits(temp, nx, ny, NULL);
    // x mod dvs와 y mod dvs를 각각 계산한다.
    mpz_mod(nx, x, dvs);
    mpz_mod(ny, y, dvs);
    if (mpz_cmp(nx, ny) < 0) {
        // nx가 ny보다 작으면 temp에 nx + dvs - ny를 저장한다.
        mpz_add(temp, nx, dvs);
        mpz_sub(temp, temp, ny);
    } else {
        // temp에 x - y를 저장한다.
        mpz_sub(temp, nx, ny);
    }
    mpz_set(result, temp); // temp의 값을 result에 저장한다.
    // 사용을 완료한 변수를 초기화한다.
    mpz_clears(temp, nx, ny, NULL);
}

/*
* mod_mul - perform modular multiplication
* (x * y) mod dvs를 계산한다.
 */
void mod_mul(mpz_t result, mpz_t x, mpz_t y, mpz_t dvs) {
    // r = (x * y) mod dvs를 계산한다.
    mpz_t r;
    mpz_init(r);
    mpz_mul(r, x, y);
    mpz_mod(r, r, dvs);
    // result에 r을 저장한다.
    mpz_set(result, r);
    // 사용 완료한 변수를 초기화한다.
    mpz_clear(r);
}

/*
* calc_point - perform addition operation for elliptic curve P-256
 */
int calc_point(ecdsa_p256_t *R, const ecdsa_p256_t *P, const ecdsa_p256_t *Q) {

    // 계산에 필요한 변수를 초기화한다.
    mpz_t x3, y3, x1, y1, x2, y2, lambda, temp;
    mpz_inits(x3, y3, x1, y1, x2, y2, lambda, temp, NULL);
    mpz_import(x1, ECDSA_P256/8, 1, 1, 1, 0, P->x);
    mpz_import(y1, ECDSA_P256/8, 1, 1, 1, 0, P->y);
    mpz_import(x2, ECDSA_P256/8, 1, 1, 1, 0, Q->x);
    mpz_import(y2, ECDSA_P256/8, 1, 1, 1, 0, Q->y);

    // 두 점의 좌표가 동일한 경우
    if(mpz_cmp(x1, x2) == 0 && mpz_cmp(y1, y2) == 0) {
        // y좌표가 0이면 O(infinity)이므로 ERROR를 반환한다.
        if (mpz_cmp_ui(y1, 0) == 0) {
            mpz_clears(x3, y3, x1, y1, x2, y2, lambda, temp, NULL);
            return ERROR;
        }

        mpz_mul_ui(temp, y1, 2); mpz_mod(temp, temp, p); // temp = 2 * y1
        mpz_invert(lambda, temp, p); // lambda = (2 * y1)^(-1) mod p

        mpz_powm_ui(temp, x1, 2, p); // temp = x1^2
        mod_mul(temp, temp, a, p);  // temp = 3 * x1^2
        mod_sub(temp, temp, a, p); // temp = 3 * x1^2 - 3, a = -3

        mod_mul(lambda, lambda, temp, p); // lambda = (lambda * temp)

        mpz_powm_ui(x3, lambda, 2, p); // x3 = lambda^2
        mpz_mul_ui(temp, x1, 2); mpz_mod(temp, temp, p); // temp = 2 * x1
        mod_sub(x3, x3, temp, p); // x3 = (lambda^2 - 2 * x1) mod p

        mpz_set(y3, lambda); // y3 = lambda
        mod_sub(temp, x1, x3, p); // temp = x1 - x3
        mod_mul(y3, y3, temp, p); // y3 = y3 * temp
        mod_sub(y3, y3, y1, p); // y3 = y3 mod p

    } else {
        if (mpz_cmp(x1, x2) == 0) {
            // qx - rx가 0이면 O(infinity)이므로 ERROR를 반환한다.
            mpz_clears(x3, y3, x1, y1, x2, y2, lambda, temp, NULL);
            return ERROR;
        } 
        mod_sub(temp, x2, x1, p); // temp = x2 - x1
        mpz_invert(temp, temp, p); // temp = (x2 - x1)^(-1) mod p
        mpz_set(lambda, temp); // lambda = temp
        mod_sub(temp, y2, y1, p); // temp = y2 - y1
        
        mod_mul(lambda, lambda, temp, p); // lambda = lambda * temp

        mpz_powm_ui(x3, lambda, 2, p); // x3 = {(y2 - y1) * (x2 - x1)^(-1)}^2 
        mod_sub(x3, x3, x1, p); // x3 = (x3 - x1) mod p
        mod_sub(x3, x3, x2, p); // x3 = (x3 - x2) mod p

        mpz_set(y3, lambda); // y3 = lambda
        mod_sub(temp, x1, x3, p); // temp = (x1 - x3) mod p
        mod_mul(y3, y3, temp, p); // y3 = (y3 * temp) mod p
        mod_sub(y3, y3, y1, p); // y3 = (y3 - y1) mod p
    }
    // 계산된 x3와 y3를 R의 x와 y에 복사한다.
    mpz_export(R->x, NULL, 1, ECDSA_P256/8, 1, 0, x3);
    mpz_export(R->y, NULL, 1, ECDSA_P256/8, 1, 0, y3);

    // 계산이 완료된 경우 mpz_t 변수들을 초기화하고 0을 반환한다.
    mpz_clears(x3, y3, x1, y1, x2, y2, lambda, temp, NULL);

    return 0;
}

/*
* generate_points - perform square multiplication using d and Q
 */
int generate_points(mpz_t d, ecdsa_p256_t *result, ecdsa_p256_t Q) {

    // 계산 결과를 임시로 담을 변수
	ecdsa_p256_t R;
    // 계산 결과와 더해지는 점이 Infinity임을 표시하는 변수
	int r_inf = ERROR, Q_inf = 0;

    // Square Multiplication : d의 비트를 모두 확인했거나 Q가 Infinity가 되면 중지한다. R은 타원곡선 상의 점이어야 한다.
    for (int i = 0 ; (i < ECDSA_P256 && !Q_inf) ; i++) { // mpz_t는 일반적인 배열처럼 MSB의 index가 0이 아니라 LSB의 index가 0이다. 
        if(mpz_tstbit(d, i)){
            // d의 i번째 비트가 존재하면
			if(r_inf){ // R에 Q를 더했을 때 infinity가 된 경우 infinity는 항등원이므로 R에 Q의 값을 저장한다. O + Q = O
                memcpy(R.x, Q.x, ECDSA_P256/8);
                memcpy(R.y, Q.y, ECDSA_P256/8);
				r_inf = 0;
			} else r_inf = calc_point(&R, &R, &Q); // R이 infinity가 아니면 R에 Q를 더한다.
			}
            Q_inf = calc_point(&Q, &Q, &Q); // d의 i번째 비트가 존재하지 않으면 Q에 Q를 더한다.
	}
    // 계산이 완료되었으면 result에 R의 값을 복사한다.
    memcpy(result->x, R.x, ECDSA_P256/8);
    memcpy(result->y, R.y, ECDSA_P256/8);

    // 만약 d * Q가 Infinity이면 오류메시지를 반환한다.
    if (Q_inf) r_inf = ERROR;
    // 계산 결과를 반환한다.
    return r_inf;
}


/*
 * ecdsa_p256_key() - generates Q = dG
 * 사용자의 개인키와 공개키를 무작위로 생성한다.
 */
void ecdsa_p256_key(void *d, ecdsa_p256_t *Q)
{
    // 시스템 파라미터의 길이가 224bit보다 짧은 경우 함수롤 종료한다.
    if (ECDSA_P256/8 < 28) return;

    // 키가 제대로 생성되었는지 확인하기 위한 값
    int bit_result = ERROR, gen_result = ERROR;

    // 난수를 생성하기 위한 state 변수와 생성된 난수를 저장하기 위한 return_bits 변수
    mpz_t return_bits; gmp_randstate_t state;

    // random state와 return_bits를 초기화한다.
    gmp_randinit_default(state);
    mpz_init(return_bits);

    // arc4random 함수를 사용하여 state에 seed를 입력한다.
    gmp_randseed_ui(state, arc4random());

    // 오류가 반환되지 않을 때까지 반복한다.
    // loop invariant : d는 n보다 작은 랜덤한 정수이어야 하고 Q는 d * G이어야 한다.
    while(bit_result || gen_result) {

        // state를 이용하여 352bit 길이만큼의 난수를 생성하고 return_bits에 저장한다.
        // The recommended minimum output-size l : 352bit
        mpz_urandomb(return_bits, state, 352);

        // return_bits를 d로 변환한다.
        bit_result = bit2int(return_bits);

        if (!bit_result) {
            // return_bits가 정상적으로 생성되었으면 Big-Endian 형식의 bit string으로 변환하여 d에 저장한다.
            mpz_export(d, NULL, 1, ECDSA_P256/8, 1, 0, return_bits);
            // d가 정상적으로 생성되었으면 Q = d * G를 계산한다. 
            // return_bits에는 d를 bit_string으로 변환하기 전의 값이 들어있다.
            gen_result = generate_points(return_bits, Q, G);
        }
    }

    // 사용완료한 변수를 초기화한다.
    mpz_clear(return_bits);
    gmp_randclear(state);
}

/*
 * ecdsa_p256_sign(msg, len, d, r, s) - ECDSA Signature Generation
 * 길이가 len 바이트인 메시지 m을 개인키 d로 서명한 결과를 r, s에 저장한다.
 * sha2_ndx는 사용할 SHA-2 해시함수 색인 값으로 SHA224, SHA256, SHA384, SHA512,
 * SHA512_224, SHA512_256 중에서 선택한다. r과 s의 길이는 256비트이어야 한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int ecdsa_p256_sign(const void *msg, size_t len, const void *d, void *_r, void *_s, int sha2_ndx)
{
    // 서명 성공 여부를 담을 반환값과 키가 제대로 생성되었는지 확인하기 위한 값
    int result = 0, bit_result, gen_result, r_result = ERROR, s_result = ERROR;

	// 메시지의 길이가 해시 함수가 처리할 수 있는 길이를 벗어난 경우 에러메시지를 반환한다.
    // 현존하는 CPU가 최대 처리할 수 있는 비트가 64비트이므로 
    // SHA-384 이상의 해시 함수는 길이를 체크하지 않아도 된다.
	if (check_length(len, sha2_ndx)) return ECDSA_MSG_TOO_LONG;
	
    // 해시 함수의 메시지 다이제스트를 담을 배열 E와 N_E를 생성한다.
    hLen = hash_output[sha2_ndx];
    unsigned char E[hLen], N_E[ECDSA_P256/8];

    // E에 해시 함수의 메시지 다이제스트를 담는다.
    calc_hash(msg, len, E, sha2_ndx);

    // bit string E(N_E)를 정수로 변환한 값을 담을 e와
    // per-message secret number를 담을 k, d의 값을 담을 nd를 생성한다.
    mpz_t e, k, nd;
    mpz_inits(e, k, nd, NULL);

    // nd에 d의 값을 저장한다.
    mpz_import(nd, ECDSA_P256/8, 1, 1, 1, 0, d);

	// 해시 함수의 메시지 다이제스트 길이가 256비트보다 긴 경우
	if (hLen > ECDSA_P256 / 8) {
		// N_E에 E의 원소를 256비트만큼 복사한다. 
        memcpy(N_E, E, ECDSA_P256/8);
        mpz_import(e, ECDSA_P256/8, 1, 1, 1, 0, N_E);
    } else {
        // 길지 않은 경우 E를 그대로 사용한다.
        mpz_import(e, hLen, 1, 1, 1, 0, E);
    }

    // 난수를 생성하기 위한 state 변수
    gmp_randstate_t state;

    // random state를 초기화한다.
    gmp_randinit_default(state);

    // arc4random 함수를 사용하여 state에 seed를 입력한다.
    gmp_randseed_ui(state, arc4random());

    // R = k * G를 담을 변수 생성
    ecdsa_p256_t R;

    // 서명 생성 시 사용할 변수들을 초기화한다.
    mpz_t xr, r, s, kinv;
    mpz_inits(xr, r, s, kinv, NULL);

    while (r_result || s_result) {
        // 오류가 반환되지 않을 때까지 반복한다.
        // loop invariant : s와 r 둘 중 하나라도 값이 0일 수 없다.
        bit_result = ERROR, gen_result = ERROR;
        while(bit_result || gen_result) {
            // loop invariant : k는 n보다 작은 랜덤한 정수이어야 한다.
            // state를 이용하여 352bit 길이만큼의 난수를 생성하고 k에 저장한다.
            // The recommended minimum output-size : 352bit
            mpz_urandomb(k, state, 352);

            // Modular Reduction
            bit_result = bit2int(k);

            // 만약 k와 nd의 값이 같다면 k를 다시 구해야한다. If k == d, s = k^(-1) * (e + dr) mod n, s = (k^(-1) * e + r) mod n 
            if (mpz_cmp(k, nd) == 0) bit_result = ERROR;
            
            if (!bit_result) {
            // k가 정상적으로 생성되었으면 R = k * G를 계산한다. 
            // return_bits에는 d를 bit_string으로 변환하기 전의 값이 들어있다.
            gen_result = generate_points(k, &R, G);
            }
        }

        // xr에 rx의 값을 복사한다.
        mpz_import(xr, ECDSA_P256/8, 1, 1, 1, 0, R.x);

        // r에 xr mod n의 값을 저장한다.
        mpz_mod(r, xr, n);

        // 만약 r이 0이 아니라면 s를 계산하도록 r_result를 0으로 설정한다.
        if (mpz_cmp_ui(r, 0) == 0) r_result = ERROR;
        else r_result = 0;

        if (!r_result) {
            // r이 0이 아니라면 s를 계산한다.
            mpz_invert(kinv, k, n); // k^(-1) mod n을 계산한다.
            
            mod_mul(s, r, nd, n); // s에 (r * d) mod n의 값을 저장한다.

            mod_add(s, s, e, n); // s에 (e + s) mod n의 값을 저장한다.

            mod_mul(s, s, kinv, n); // s에 (s * k^(-1)) mod n의 값을 저장한다.

            // 만약 s가 0이 아니라면 루프를 종료하도록 s_result를 0으로 설정한다.
            if (mpz_cmp_ui(s, 0) == 0) s_result = ERROR;
            else s_result = 0;
        }

        if (!r_result && !s_result) {
            // r과 s가 정상적으로 생성되었으면 _r에 r을 _s에 s를 저장한다.
            mpz_export(_r, NULL, 1, ECDSA_P256/8, 1, 0, r);
            mpz_export(_s, NULL, 1, ECDSA_P256/8, 1, 0, s);
        }
    }
    // 사용을 완료한 변수를 초기화한다.
    mpz_clears(e, k, xr, r, s, kinv, nd, NULL);
    gmp_randclear(state);

    return result;
}

/*
 * ecdsa_p256_verify(msg, len, Q, r, s) - ECDSA signature veryfication
 * It returns 0 if valid, nonzero otherwise.
 * 길이가 len 바이트인 메시지 m에 대한 서명이 (r,s)가 맞는지 공개키 Q로 검증한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int ecdsa_p256_verify(const void *msg, size_t len, const ecdsa_p256_t *_Q, const void *_r, const void *_s, int sha2_ndx)
{
    // 메시지의 길이가 해시 함수가 처리할 수 있는 길이를 벗어난 경우 에러메시지를 반환한다.
    // 현존하는 CPU가 최대 처리할 수 있는 비트가 64비트이므로 
    // SHA-384 이상의 해시 함수는 길이를 체크하지 않아도 된다.
	if (check_length(len, sha2_ndx)) return ECDSA_MSG_TOO_LONG;

    // _r, _s의 값을 복사할 변수를 생성하고 초기화한다.
    mpz_t r, s;
    mpz_inits(r, s, NULL);
    // _r의 값을 r에 _s의 값을 s에 복사한다.
    mpz_import(r, ECDSA_P256/8, 1, 1, 1, 0, _r);
    mpz_import(s, ECDSA_P256/8, 1, 1, 1, 0, _s);

    // r과 s의 값이 [1, n-1] 사이의 값이 아니면 오류메시지를 반환한다.
    if (mpz_cmp_ui(r, 0) <= 0 || mpz_cmp(r, n) >= 0) {
        mpz_clears(r, s, NULL);
        return ECDSA_SIG_INVALID;
    }
    if (mpz_cmp_ui(s, 0) <= 0 || mpz_cmp(s, n) >= 0) {
        mpz_clears(r, s, NULL);
        return ECDSA_SIG_INVALID;
    }

    // 해시 함수의 메시지 다이제스트를 담을 배열 E와 N_E를 생성한다.
    hLen = hash_output[sha2_ndx];
    unsigned char E[hLen], N_E[ECDSA_P256/8];

    // 서명 검증과 계산 결과가 제대로 생성되었는지 확인하기 위한 값
    int result = 0;

    // E에 해시 함수의 메시지 다이제스트를 담는다.
    calc_hash(msg, len, E, sha2_ndx);

    // bit string E(N_E)를 정수로 변환한 값을 담을 e를 생성한다.
    mpz_t e;
    mpz_inits(e, NULL);

    // E에 해시 함수의 메시지 다이제스트를 담는다.
    calc_hash(msg, len, E, sha2_ndx);

	// 해시 함수의 메시지 다이제스트 길이가 256비트보다 긴 경우
	if (hLen > ECDSA_P256 / 8) {
		// N_E에 E의 원소를 256비트만큼 복사한다. 
        memcpy(N_E, E, ECDSA_P256/8);
        mpz_import(e, ECDSA_P256/8, 1, 1, 1, 0, N_E);
    } else {
        // 길지 않은 경우 E를 그대로 사용한다.
        mpz_import(e, hLen, 1, 1, 1, 0, E);
    }

    // s^(-1)을 담을 sinv, (e * sinv) mod n을 담을 u, 
    // (r * sinv) mod n을 담을 v를 생성한다.
    mpz_t sinv, u, v;
    mpz_inits(sinv, u, v, NULL);
    // s^(-1) mod n을 계산하여 sinv에 저장한다.
    mpz_invert(sinv, s, n);
    // (e * sinv) mod n을 계산하여 u에 저장한다.
    mod_mul(u, e, sinv, n);
    // (r * sinv) mod n을 계산하여 v에 저장한다.
    mod_mul(v, r, sinv, n);

    // u * G와 v * Q를 담을 ug와 vq와 ug + vq를 담을 R을 생성한다.
    ecdsa_p256_t ug, vq, R;

    // u * G를 계산하여 ug에 저장한다.
    result = generate_points(u, &ug, G);
    if (result) { 
        // 계산된 점이 infinity인 경우 오류메시지를 반환한다.
        mpz_clears(r, s, e, sinv, u, v, NULL);
        return ECDSA_SIG_INVALID;
    }
    // v * Q를 계산하여 vq에 저장한다.
    result = generate_points(v, &vq, *_Q); // 포인터이므로 *을 붙여 값을 전달
    if (result) {
        // 계산된 점이 infinity인 경우 오류메시지를 반환한다.
        mpz_clears(r, s, e, sinv, u, v, NULL);
        return ECDSA_SIG_INVALID;
    }
    // u * G, v * Q의 각 좌표를 담을 변수들을 생성하고 초기화한다.
    mpz_t rx;
    mpz_inits(rx, NULL);

    // ugx + vqx를 ugx에, ugy + vqy를 ugy에 저장한다.
    result = calc_point(&R, &ug, &vq);
    if (result) {
        // 계산된 점이 infinity인 경우 오류메시지를 반환한다.
        mpz_clears(r, s, e, sinv, u, v, rx, NULL);
        return ECDSA_SIG_INVALID;
    }
    // x 좌표를 rx에 저장한다.
    mpz_import(rx, ECDSA_P256/8, 1, 1, 1, 0, R.x);

    // rx mod n을 계산한다.
    mpz_mod(rx, rx, n);

    if (mpz_cmp(rx, r) == 0) {
        // 만약 rx가 r과 같으면 성공 메시지를 반환한다.
        mpz_clears(r, s, e, sinv, u, v, rx, NULL);
        return result;
    } else {
        // 아닌 경우 서명에 오류가 있으므로 오류 메시지를 반환한다.
        mpz_clears(r, s, e, sinv, u, v, rx, NULL);
        return ECDSA_SIG_MISMATCH;
    }
}

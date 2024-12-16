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
#include "mRSA.h"

/*
 * mod_add() - computes a + b mod m
 */
static uint64_t mod_add(uint64_t a, uint64_t b, uint64_t m)
{   

    // a와 b를 m으로 각각 나눈 나머지를 구합니다.
    a %= m, b %= m;
    // a + b >= m일 때는 오버플로 방지를 위해 (a - (m - b))를 반환하고 a + b <= m인 경우에는 a + b를 반환합니다.
    return (a >= m - b) ? (a - (m - b)) : (a + b);
}

/*
 * mod_sub() - computes a-b mod m
 * 만일 a < b이면 결과가 음수가 되므로 m을 더해서 양수로 만든다.
 */
static uint64_t mod_sub(uint64_t a, uint64_t b, uint64_t m)
{
    // a와 b를 m으로 각각 나눈 나머지를 구합니다.
    a %= m, b %= m;
    // a < b인 경우 결과가 음수가 되므로 a - b + m을 한 결과를 반환하고 a >= b인 경우 결과는 양수이므로 a + b를 반환합니다.
    return (a < b) ? (a + (m - b)) : (a - b);
}

/*
 * mod_mul() - computes a * b mod m
 */
static uint64_t mod_mul(uint64_t a, uint64_t b, uint64_t m)
{
    // 나머지를 담을 변수를 0으로 초기화합니다(비트 연산과 덧셈을 활용하므로).
    uint64_t r = 0;
    // b가 0보다 클 동안 반복합니다.
    while (b > 0) {
        // b를 비트로 표현했을 때 맨 왼쪽 비트가 존재하면
        if (b & 1)
            // mod_add를 이용해 나머지에 a를 더하고 m으로 나눈 나머지를 구합니다.
            r = mod_add(r, a, m);
        // b를 왼쪽으로 1비트 shift 합니다.
        b = b >> 1;
        // a에 a를 더하고 m으로 나눈 나머지를 구합니다.
        a = mod_add(a, a, m);
    }
    return r;
}

/*
 * mod_pow() - computes a^b mod m
 */
static uint64_t mod_pow(uint64_t a, uint64_t b, uint64_t m)
{
    // 나머지를 담을 변수를 1로 초기화합니다(곱하기 이므로).
    uint64_t r = 1;
    // b가 0보다 클 동안 반복합니다.
    while (b > 0) {
        // b를 비트로 표현했을 때 맨 왼쪽 비트가 존재하면
        if (b & 1)
            // 나머지에 a를 곱하고 m으로 나눈 나머지를 구합니다.
            r = mod_mul(r, a, m);
        // b를 왼쪽으로 1 비트 shift 합니다.
        b = b >> 1;
        // a에 a를 더하고 m으로 나눈 나머지를 구합니다.
        a = mod_mul(a, a, m);
    }
    return r;
}

/*
 * gcd() - Euclidean algorithm
 */
static uint64_t gcd(uint64_t a, uint64_t b)
{
    // a, b, q, r이 정수일 때 a = bq + r이면 gcd(a, b) = gcd(b, r)이다.
    // a와 b 중 한 숫자가 0이 될 때까지 반복합니다.
    while (1)
        // 만약 a가 0이면 b가 최대공약수이므로 b를 반환합니다.
        if (a == 0)
            return b;
        // 만약 b가 0이면 a가 최대공약수이므로 a를 반환합니다. 
        else if (b == 0)
            return a;
        // a와 b 두 숫자 모두 0이 아닌 경우 
        else
            // a가 b보다 크면 a를 b로 나눈 나머지를 구합니다.
            if (a > b)
                a = a % b;
            // a가 b보다 같거나 작으면 b를 a로 나눈 나머지를 구합니다.
            else
                b = b % a;
}

/*
 * umul_inv() - computes multiplicative inverse a^-1 mod m
 * It returns 0 if no inverse exist.
 */
static uint64_t umul_inv(uint64_t a, uint64_t m)
{
    // uint64_t(2^64) : 0 ~ 18,446,744,073,709,551,615(ULL) <-> int64_t(2^63) : −9,223,372,036,854,775,808 에서 9,223,372,036,854,775,807
    // int64_t의 맨 왼쪽 비트는 부호를 나타내므로 계산할 때 주의해야 한다.
    // 선형 합동 : a와 m이 서로소이고 m > 1이면 a 모듈로 m의 역이 존재한다. 또한 a 모듈로 m의 역은 유일하다.
    // 점화식 : [x(i) = x(i-2) - q(i) * x(i-1)] / [y(i) = y(i-2) - q(i) * y(i-1)]
    // 점화식 구성을 위해 x0, x1, y0, y1을 초기화합니다. / 최종 계산 결과를 담을 x, y 변수를 초기화 합니다.
    int64_t x0 = 1, x1 = 0, y0 = 0, y1 = 1, x; 
    // 몫을 담을 q와 새롭게 계산된 x를 담을 temp 변수를 초기화합니다. / a가 m보다 큰지 작은지를 판단하는 big_a 변수를 초기화합니다.
    // m의 값을 저장할 새로운 변수 n_m을 초기화합니다.
    int64_t q, temp, big_a = 1; uint64_t n_m = m;
    // m이 1과 같거나 작은 경우 0을 반환합니다.
    if (m <= 1) {
        return 0;
    } else {
        // a가 m보다 크거나 같으면 big_a를 1로, a가 m보다 작으면 big_a를 0으로 설정합니다.
        if (a < m) {
            big_a = 0;
        }
        while (1) {
            // 마지막에서 두번째로 계산된 x, y가 정답입니다(마지막 계산 -> [r(n-1) = q(n+1) * r(n) + 0]).
            // 입력으로 주어진 a가 m보다 크거나 같으면 m이 처음으로 몫이 됩니다.
            if (big_a == 1) {
                x = x0;
            // 입력으로 주어진 a가 m보다 크거나 같으면 a가 처음으로 몫이 됩니다.
            } else {
                x = y0;
            }
            // 만약 a가 0이면 m이 1이 아닌 경우 0을 반환합니다.
            if (a == 0) {
                if (m != 1) {
                    return 0;
                } else {
                    // 그 외의 경우 x가 0보다 큰 경우 x를 반환하고 x가 0보다 작은 경우 (n_m + x) % n_m을 반환합니다.
                    if (x > 0) {
                        return x;
                    } else {
                        return (n_m + x) % n_m;
                    }
                }
            // 만약 m이 0이면 a가 1이 아닌 경우 0을 반환합니다.
            } else if (m == 0) {
                if (a != 1) {
                    return 0;
                } else {
                    // 그 외의 경우 x가 0보다 큰 경우 x를 반환하고 x가 0보다 작은 경우 (n_m + x) % n_m을 반환합니다.
                    // m이 0인 경우에도 n_m으로 나누는 이유는 umul_inv함수가 a^-1 mod m을 구하는 함수이기 때문이다.
                    if (x > 0) {
                        return x;
                    } else {
                        return (n_m + x) % n_m;
                    }
                }
            // a와 m 두 숫자 모두 0이 아닌 경우 
            } else {
                // a가 m보다 크면 a를 m으로 나눈 나머지를 구합니다.
                if (a > m) {
                    q = a / m;
                    a = a % m;
                // m가 a보다 크면 m을 a로 나눈 나머지를 구합니다.
                } else {
                    q = m / a;
                    m = m % a;              
                }
            }
            // 계산된 몫과 기존의 x0, x1을 활용해 새로운 x를 계산하고 x0는 x1으로 x1은 temp로 치환합니다.
            temp = x0 - (q * x1);
            x0 = x1;
            x1 = temp;
            // 계산된 몫과 기존의 y0, y1을 활용해 새로운 y를 계산하고 y0는 y1으로 y1은 temp로 치환합니다.
            temp = y0 - (q * y1);
            y0 = y1;
            y1 = temp;
        }
    }
}

/*
 * Miller-Rabin Primality Testing against small sets of bases
 *
 * if n < 2^64,
 * it is enough to test a = 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, and 37.
 *
 * if n < 3317044064679887385961981,
 * it is enough to test a = 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, and 41.
 */
// static const uint64_t a[BASELEN] = {2,3,5,7,11,13,17,19,23,29,31,37};

/*
 * miller_rabin() - Miller-Rabin Primality Test (deterministic version)
 *
 * n > 3, an odd integer to be tested for primality
 * It returns 1 if n is prime, 0 otherwise.
 */
int miller(uint64_t n, const uint64_t *a, int length) {
    // Any positive odd integer n >= 3, n - 1 = 2^k * q(k > 0, n - 1 is even, q is odd)
    // 계산에 필요한 변수들을 초기화합니다.
    uint64_t k = 0, q = n - 1, x, y;
    // q의 초기값은 짝수인 n - 1입니다. q의 값이 홀수일 때까지 2로 나눠주고 k에 1을 더합니다.
     while (q % 2 == 0) {
        q /= 2;
        k++;
    }
    // length를 활용하여 배열에서 필요한 수만 골라서 연산을 진행합니다.
    for (int i = 0 ; i < length ; i++) {
        // n이 배열에 담긴 수와 같으면 배열에 담긴 수들은 소수이므로 n도 소수입니다.
        if (n == a[i])
            return PRIME;
        // 상기 조건을 거친 상태에서 n이 배열에 담긴 수로 나눠진다면 n은 합성수입니다.
        if (n % a[i] == 0)
            return COMPOSITE;
        // 배열에 담긴 수가 n보다 큰 경우 계산이 불필요하므로 for 구문을 종료합니다.
        if (a[i] > n)
            break;
        // First property : If n is prime and a is a positive integer less than n, then
        // a^2 mod n = 1 if and only if either a mod n = 1 or a mod n = -1 mod n = n - 1.

        // Second property : Let n be a prime number greater than 2. n - 1 = 2^k * q with k > 0, q odd. 
        // Let a be any integer in the range 1 < a < n - 1. a^q is congruent to 1 modulo n. That is, a^q mod n = 1.
        // One of the numbers a^q, a^2q, a^4q, ... , a^(2^(k-1)*q) is congruent to -1 modulo n = n - 1.

        // a^q를 계산하여 x에 저장합니다.
        x = mod_pow(a[i], q, n);
        for (int j = 0 ; j < k ; j++) {
            // a^q, a^2q, a^4q, ... 순으로 계산합니다.
            y = mod_pow(x, 2, n);
            // First property 의거 y(a^2)가 1이면서 x(a)가 1 또는 n - 1이 아닌 경우 n은 합성수입니다.
            if (y == 1 && x != 1 && x != (n - 1))
                return COMPOSITE;
            // 다음 루프에서 계산에 사용하기 위해 x에 y의 값을 대입합니다.
            x = y;
            }
        // 페르마의 정리에 의거 y가 1이 아닌 경우 합성수입니다(y는 a^((2^k)*q) % n이므로 n이 소수인 경우 1이어야 합니다, (2^k)*q) = n - 1).
        if (y != 1)
            return COMPOSITE;
        }
    // 테스트를 이상 없이 통과했으면 소수입니다.
    return PRIME;
}

int miller_rabin(uint64_t n)
{   
    // miller 함수에서 반환하는 결과값을 담을 변수를 초기화합니다.
    int determine;
    // n이 1보다 작은 경우 소수가 아닙니다.
    if (n <= 1)
        return COMPOSITE;
    // n이 2이면 소수입니다.
    else if (n == 2)
        return PRIME;
    else {
        // n이 2로 나누어지면 소수가 아닙니다.
        if (n % 2 == 0)
            return COMPOSITE;
        else {
            // n이 특정한 수보다 작은 경우 모든 범위(1 < n - 1)의 수를 계산할 필요는 없습니다.
            // miller 함수를 이용하여 소수인지 판별한 후 결과를 반환합니다.
            if (n < 2047){   
                const uint64_t a[] = {2};
                determine = miller(n, a, 1);
            } else if (n < 1373653) {
                const uint64_t a[] = {2, 3};
                determine = miller(n, a, 2);
            } else if (n < 9080191) {
                const uint64_t a[] = {31, 73};
                determine = miller(n, a, 2);
            } else if (n < 25326001) {
                const uint64_t a[] = {2, 3, 5};
                determine = miller(n, a, 3);
            } else if (n < 3215031751) {
                const uint64_t a[] = {2, 3, 5, 7};
                determine = miller(n, a, 4);
            } else if (n < 4759123141) {
                const uint64_t a[] = {2, 7, 61};
                determine = miller(n, a, 3);
            } else if (n < 1122004669633) {
                const uint64_t a[] = {2, 13, 23, 1662803};
                determine = miller(n, a, 4);
            } else if (n < 2152302898747) {
                const uint64_t a[] = {2, 3, 5, 7, 11};
                determine = miller(n, a, 5);
            } else {
                const uint64_t a[BASELEN] = {2,3,5,7,11,13,17,19,23,29,31,37};
                if (n < 3474749660383) {
                    determine = miller(n, a, 6);
                } else if (n < 341550071728321) {
                        determine = miller(n, a, 7);
                } else if (n < 3825123056546413051) {
                        determine = miller(n, a, 9);
                } else {
                    determine = miller(n, a, BASELEN);
                }
            }
        return determine;
        }
    }
}

/*
 * mRSA_generate_key() - generates mini RSA keys e, d and n
 *
 * Carmichael's totient function Lambda(n) is used.
 */
void mRSA_generate_key(uint64_t *e, uint64_t *d, uint64_t *n, uint64_t *p, uint64_t *q, uint64_t *dp, uint64_t *dq, uint64_t *qinv, uint64_t *pinv)
{
    // 키 계산을 위해 사용될 변수들을 초기화합니다.
    // p, q : 서로 다른 32bit 내외의 소수, num : 랜덤으로 생성할 2^32 - 1 이하의 수
    // carmc : 공개키와 암호키로 사용할 e와 d를 산출하기 위한 lambda(n)
    // new_e : 1보다 크고 lambda(n)보다 작으며 gcd(e, lambda(n)) = 1인 e를 구하기 위해 사용할 32비트 이하의 난수
    *p = 0, *q = 0; uint64_t new_e, carmc;
    uint32_t num;
    // p와 q가 구해질 때까지 반복합니다.
    while (1) {
        // 랜덤으로 2^32 - 1 이하의 수를 생성합니다.
        arc4random_buf(&num, sizeof(uint32_t));
        // 만약 생성한 난수가 소수이면
        if (miller_rabin(num)) {
            // p가 0인 경우에는 p의 값을 해당 난수로 설정합니다.
            if (*p == 0)
                *p = num;
            // q가 0인 경우에는 q의 값을 해당 난수로 설정합니다.
            else
                *q = num;
        }
        // p와 q가 서로 다른 소수이면
        if (*p != 0 && *q != 0 && *p != *q) {
            // n의 값을 p와 q를 곱한 수로 설정합니다.
            *n = *p * *q;
            // 만약 n이 2^63보다 같거나 크고 2^64보다 작다면 RSA 키를 생성하기 위한 조건이
            // 만족되었으므로 while 루프를 종료합니다.
            if ((*n >= MINIMUM_N) && (*n <= 18446744073709551615UL)){ // 9223372036854775808UL
                break;
            }
            // 만약 n이 2^63보다 작거나 2^64보다 크다면 p와 q를 0으로 초기화하여
            // 다른 조합을 구합니다.
            else {
                *p = 0, *q = 0;
            }
        }
    }
    // 카마이클 함수를 활용하여 lambda(n)을 구합니다.
    carmc = ((*p - 1) * (*q - 1)) / gcd(*p - 1, *q - 1);
    // RSA 암호체계에서 e로 가장 자주 사용되는 값은 65537입니다. 
    new_e = 65537;
    // 만약 계산된 lambda(n)과 65537이 서로소이면 e의 값으로 65537을 설정합니다.
    if (gcd(65537, carmc) == 1) {
        *e = new_e;
    // lamda(n)과 65537이 서로소가 아니면
    } else {
    // 새로운 e가 구해질 때까지 반복합니다.
        while (1) {
            // lambda(n)보다 작은 난수를 생성합니다.
            new_e = arc4random_uniform(carmc);
            // 만약 생성한 난수가 1보다 크고 lambda(n)보다 작을 때
            if (( 1 < new_e && new_e < carmc) ){ 
                // lambda(n)과 생성한 난수가 서로소이면
                if (gcd(new_e, carmc) == 1) {
                    // e의 값을 생성한 난수로 설정하고 while 루프를 종료합니다.
                    *e = new_e;
                    break;
                }
            }
        }
    }
    // d는 e mod lambda(n)의 inverse입니다.
    *d = umul_inv(*e, carmc);
    // Chinese Remainder Theorem을 활용하여 복호화를 할 수 있도록 qinv, dp, dq를 계산합니다.
    // 페르마의 정리에 의해 a^(p-1) mod p = 1 mod p이므로 a^(d mod (p-1)) mod p = a^d (mod p)입니다.
    // 지수를 d 대신 d % (p - 1), d % (q - 1)로 줄일 수 있습니다.
    *dp = *d % (*p - 1);
    *dq = *d % (*q - 1);
    *qinv = umul_inv(*q, *p);
    *pinv = umul_inv(*p, *q);
}

/*
 * mRSA_cipher() - compute m^k mod n
 *
 * If data >= n then returns 1 (error), otherwise 0 (success).
 */
int mRSA_cipher(uint64_t *m, uint64_t k, uint64_t n)
{
    // 암호화 성공 여부를 반환할 변수를 초기화합니다.
    int result = 1;
    // 평문은 n의 크기를 넘을 수 없습니다.
    // 넘는 경우 1을 리턴합니다.
    if (*m >= n) {
        return result;
    }
    // 공개키를 활용하여 m^k mod n을 구합니다(k는 공개키). 인증 시에는 송신자가 인증수단을 개인키로 암호화해야합니다.
    *m = mod_pow(*m, k, n);
    // 만약 계산된 결과가 n보다 작다면 오류가 발생하지 않았으므로
    // result의 값을 0으로 설정합니다.
    if (*m < n) {
        result = 0;
    }
    return result;
}

/*
 * mRSA_decipher() - compute m^k mod n
 *
 * If data >= n then returns 1 (error), otherwise 0 (success).
 */
int mRSA_decipher(uint64_t *m, uint64_t k, uint64_t n, uint64_t p, uint64_t q, uint64_t dp, uint64_t dq, uint64_t qinv, uint64_t pinv)
{
    // CRT를 활용하여 복호화할 때 사용할 변수들을 초기화합니다.
    uint64_t m1, m2; uint64_t h;
    // 복호화 성공 여부를 반환할 변수를 초기화합니다.
    int result = 1;
    // 암호문은 n의 크기를 넘을 수 없습니다.
    // 넘는 경우 1을 리턴합니다.
    if (*m >= n || *m < 0) {
        return result;
    }
    // 개인키를 활용하여 m^k mod n을 구합니다(k는 개인키). 인증 시에는 수신자가 송신자의 공개키로 복호화합니다.
    // m^dp mod p와 m^dq mod q를 구합니다.
    // 줄어든 지수(dp, dq)를 사용하면 계산 시간을 단축할 수 있습니다.
    m1 = mod_pow(*m, dp, p);
    m2 = mod_pow(*m, dq, q);
    // // m1 - m2를 뺀 값과 qinv를 곱합니다. m2가 m1보다 큰 경우를 대비해 mod_sub 함수를 사용하여 계산합니다.
    // // qinv * (m1 - m2)를 할 때에도 곱의 값이 64비트를 넘어갈 수 있으므로 mod_mul을 사용하여 계산합니다. 
    // // m1과 m2는 각각 mod p와 mod q로 얻은 결과이므로 m1과 m2를 단순히 더하면 mod N에서의 결과를 얻을 수 없습니다.
    // // (m1 - m2)에 q^-1 mod p를 곱하여 모듈러스 p에서의 보정 값을 구하고, 그 값에 q를 곱해 두 모듈로 값을 결합합니다.
    h = mod_mul(qinv, mod_sub(m1, m2, p), p);
    // 이 값과 m2를 더하면 평문을 구할 수 있습니다.
    *m = (m2 + (h * q));

    // CRT에 의해 M mod N = ((m1 * n2 * n2^-1 mod n1) + (m2 * n1 * n1^-1 mod n2)) mod N이다. / N = n1 * n2(n1, n2는 서로소)
    // *m = mod_add(mod_mul(mod_mul(m1, q, n), qinv, n), mod_mul(mod_mul(m2, p, n), pinv, n), n);
    // 만약 계산된 결과가 n보다 작다면 오류가 발생하지 않았으므로
    // result의 값을 0으로 설정합니다.
    if (*m < n) {
        result = 0;
    }
    return result;
}


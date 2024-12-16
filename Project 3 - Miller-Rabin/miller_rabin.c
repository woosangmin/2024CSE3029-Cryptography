/*
 * Copyright(c) 2020-2024 All rights reserved by Heekuck Oh.
 * 이 프로그램은 한양대학교 ERICA 컴퓨터학부 학생을 위한 교육용으로 제작되었다.
 * 한양대학교 ERICA 학생이 아닌 자는 이 프로그램을 수정하거나 배포할 수 없다.
 * 프로그램을 수정할 경우 날짜, 학과, 학번, 이름, 수정 내용을 기록한다.
 */

/* 
* By the grace of the Lord
* https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test
*/

#include "miller_rabin.h"

/*
 * mod_add() - computes a+b mod m
 * a와 b가 m보다 작다는 가정하에서 a+b >= m이면 결과에서 m을 빼줘야 하므로
 * 오버플로가 발생하지 않도록 a-(m-b)를 계산하고, 그렇지 않으면 그냥 a+b를 계산하면 된다.
 * a+b >= m을 검사하는 과정에서 오버플로가 발생할 수 있으므로 a >= m-b를 검사한다.
 */
uint64_t mod_add(uint64_t a, uint64_t b, uint64_t m)
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
uint64_t mod_sub(uint64_t a, uint64_t b, uint64_t m)
{
    // a와 b를 m으로 각각 나눈 나머지를 구합니다.
    a %= m, b %= m;
    // a < b인 경우 결과가 음수가 되므로 a - b + m을 한 결과를 반환하고 a >= b인 경우 결과는 양수이므로 a + b를 반환합니다.
    return (a < b) ? (a + (m - b)) : (a - b);
}

/*
 * mod_mul() - computes a*b mod m
 * a*b에서 오버플로가 발생할 수 있기 때문에 덧셈을 사용하여 빠르게 계산할 수 있는
 * "double addition" 알고리즘을 사용한다. 그 알고리즘은 다음과 같다.
 *     r = 0;
 *     while (b > 0) {
 *         if (b & 1)
 *             r = mod_add(r, a, m);
 *         b = b >> 1;
 *         a = mod_add(a, a, m);
 *     }
 */
uint64_t mod_mul(uint64_t a, uint64_t b, uint64_t m)
{
    // 나머지를 담을 변수를 0으로 초기화합니다(더하기 이므로).
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
 * a^b에서 오버플로가 발생할 수 있기 때문에 곱셈을 사용하여 빠르게 계산할 수 있는
 * "square multiplication" 알고리즘을 사용한다. 그 알고리즘은 다음과 같다.
 *     r = 1;
 *     while (b > 0) {
 *         if (b & 1)
 *             r = mod_mul(r, a, m);
 *         b = b >> 1;
 *         a = mod_mul(a, a, m);
 *     }
 */
uint64_t mod_pow(uint64_t a, uint64_t b, uint64_t m)
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
 * Miller-Rabin Primality Testing against small sets of bases
 *
 * if n < 2^64,
 * it is enough to test a = 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, and 37.
 *
 * if n < 3,317,044,064,679,887,385,961,981,
 * it is enough to test a = 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, and 41.
 */
/*
 * miller_rabin() - Miller-Rabin Primality Test (deterministic version)
 *
 * n > 3, an odd integer to be tested for primality
 * It returns PRIME if n is prime, COMPOSITE otherwise.
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

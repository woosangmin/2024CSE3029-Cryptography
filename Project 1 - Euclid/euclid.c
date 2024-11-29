/*
 * Copyright(c) 2020-2024 All rights reserved by Heekuck Oh.
 * 이 프로그램은 한양대학교 ERICA 컴퓨터학부 학생을 위한 교육용으로 제작되었다.
 * 한양대학교 ERICA 학생이 아닌 자는 이 프로그램을 수정하거나 배포할 수 없다.
 * 프로그램을 수정할 경우 날짜, 학과, 학번, 이름, 수정 내용을 기록한다.
 * 날짜 : 20240909 / 학과 : 컴퓨터학부 / 이름 : 우상민 
 * 수정 내용
 *   - 20240906 / gcd(), xgcd(), umul_inv(), mul_inv(), gf16_mul(), gf16_pow(), gf16_inv() 함수 작성(주석 포함)
 *   - 20240909 / 코드 중 사용하지 않는 변수 삭제
 */

/* 
* By the grace of the Lord
*/

#include "euclid.h"

/*
 * gcd() - Euclidean algorithm
 *
 * 유클리드 알고리즘 gcd(a,b) = gcd(b,a mod b)를 사용하여 최대공약수를 계산한다.
 * 만일 a가 0이면 b가 최대공약수가 된다. 그 반대도 마찬가지이다.
 * a, b가 모두 음이 아닌 정수라고 가정한다.
 * 재귀함수 호출을 사용하지 말고 while 루프를 사용하여 구현하는 것이 빠르고 좋다.
 */
int gcd(int a, int b)
{   
    // a, b, q, r이 정수일 때 a = bq + r이면 gcd(a, b) = gcd(b, r)이다.
    // a와 b 중 한 숫자가 0이 될 때까지 반복합니다.
    while (1) {
        // 만약 a가 0이면 b가 최대공약수이므로 b를 반환합니다.
        if (a == 0) {
            return b;
        // 만약 b가 0이면 a가 최대공약수이므로 a를 반환합니다. 
        } else if (b == 0) {
            return a;
        // a와 b 두 숫자 모두 0이 아닌 경우 
        } else {
            // a가 b보다 크면 a를 b로 나눈 나머지를 구합니다.
            if (a > b) {
                a = a % b;
            // a가 b보다 같거나 작으면 b를 a로 나눈 나머지를 구합니다.
            } else {
                b = b % a;
            }
        }
    }
}

/*
 * xgcd() - Extended Euclidean algorithm
 *
 * 확장유클리드 알고리즘은 두 수의 최대공약수 gcd(a,b) = ax + by 식을
 * 만족하는 x와 y를 계산하는 알고리즘이다. 강의노트를 참조하여 구현한다.
 * a, b가 모두 음이 아닌 정수라고 가정한다.
 */
int xgcd(int a, int b, int *x, int *y)
{   
    // 베주의 정리 : a와 b가 양의 정수이면 gcd(a, b) = sa + tb인 s와 t가 존재한다. 정수 s와 t는 a와 b의 베주 계수이다.
    // 점화식 : [x(i) = x(i-2) - q(i) * x(i-1)] / [y(i) = y(i-2) - q(i) * y(i-1)]
    // 점화식 구성을 위해 x0, x1, y0, y1을 초기화합니다.
    int x0 = 1, x1 = 0, y0 = 0, y1 = 1; 
    // 몫을 담을 q와 새롭게 계산된 x를 담을 temp 변수를 초기화합니다. / a가 b보다 큰지 작은지를 판단하는 big_a 변수를 설정합니다.
    int q, temp, big_a = 1;
    // a가 b보다 크거나 같으면 big_a를 1로, a가 b보다 작으면 big_a를 0으로 설정합니다(x와 y의 위치 선정에 필요함).
    if (a < b) {
        big_a = 0;
    }
    // a와 b 중 한 숫자가 0이 될 때까지 반복합니다.
    while (1) {
        // 마지막에서 두번째로 계산된 x, y가 정답입니다(마지막 계산 -> [r(n-1) = q(n+1) * r(n) + 0]).
        // 입력으로 주어진 a가 b보다 크거나 같으면 b가 처음으로 몫이 됩니다.
        if (big_a == 1) {
            *x = x0; *y = y0;
        // 반대로 입력으로 주어진 a가 b보다 작으면 a가 처음으로 몫이 됩니다.
        } else {
            *x = y0; *y = x0;
        }
        // 만약 a가 0이면 b가 최대공약수이므로 b를 반환합니다.
        if (a == 0) {
            return b;
        // 만약 b가 0이면 a가 최대공약수이므로 a를 반환합니다. 
        } else if (b == 0) {
            return a;
        // a와 b 두 숫자 모두 0이 아닌 경우 
        } else {
            // a가 b보다 크면 a를 b로 나눈 나머지를 구합니다.
            if (a > b) {
                q = a / b;
                a = a % b;
            // a가 b보다 같거나 작으면 b를 a로 나눈 나머지를 구합니다.
            } else {
                q = b / a;
                b = b % a;              
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

/*
 * mul_inv() - computes multiplicative inverse a^-1 mod m
 *
 * 모듈로 m에서 a의 곱의 역인 a^-1 mod m을 구한다.
 * 만일 역이 존재하지 않으면 0을 리턴한다.
 * 확장유클리드 알고리즘을 변형하여 구현한다. 강의노트를 참조한다.
 */
int mul_inv(int a, int m)
{
    // 선형 합동 : a와 m이 서로소이고 m > 1이면 a 모듈로 m의 역이 존재한다. 또한 a 모듈로 m의 역은 유일하다.
    // m이 1과 같거나 작은 경우 0을 반환합니다.
    if (m <= 1) {
        return 0;
    } else {
        // 점화식 : [x(i) = x(i-2) - q(i) * x(i-1)] / [y(i) = y(i-2) - q(i) * y(i-1)]
        // 점화식 구성을 위해 x0, x1, y0, y1을 초기화합니다. / 최종 계산 결과를 담을 x, y 변수를 초기화 합니다.
        int x0 = 1, x1 = 0, y0 = 0, y1 = 1, x; 
        // 몫을 담을 q와 새롭게 계산된 x를 담을 temp 변수를 초기화합니다. / a가 m보다 큰지 작은지를 판단하는 big_a 변수를 초기화합니다.
        // m의 값을 저장할 새로운 변수 n_m을 초기화합니다.
        int q, temp, big_a = 1, n_m = m;
        // a가 m보다 크거나 같으면 big_a를 1로, a가 m보다 작으면 big_a를 0으로 설정합니다(x와 y의 위치 선정에 필요함).
        if (a < m) {
            big_a = 0;
        }
        // a와 m 중 한 숫자가 0이 될 때까지 반복합니다.
        while (1) {
            // 마지막에서 두번째로 계산된 x, y가 정답입니다(마지막 계산 -> [r(n-1) = q(n+1) * r(n) + 0]).
            // 입력으로 주어진 a가 m보다 크거나 같으면 m이 처음으로 몫이 됩니다.
            if (big_a == 1) {
                x = x0;
            // 반대로 입력으로 주어진 a가 m보다 작으면 a가 처음으로 몫이 됩니다.
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
 * umul_inv() - computes multiplicative inverse a^-1 mod m
 *
 * 입력이 unsigned 64 비트 정수일 때 모듈로 m에서 a의 곱의 역인 a^-1 mod m을 구한다.
 * 만일 역이 존재하지 않으면 0을 리턴한다. 확장유클리드 알고리즘을 변형하여 구현한다.
 * 입출력 모두가 unsigned 64 비트 정수임에 주의한다.
 */
uint64_t umul_inv(uint64_t a, uint64_t m)
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

// /*
//  * gf16_mul(a, b) - a * b mod x^16+x^5+x^3+x+1
//  *
//  * 15차식 다항식 a와 b를 곱하고 결과를 16차식 x^16+x^5+x^3+x+1로 나눈 나머지를 계산한다.
//  * x^16 = x^5+x^3+x+1 (mod x^16+x^5+x^3+x+1) 특성을 이용한다.
//  */
uint16_t gf16_mul(uint16_t a, uint16_t b)
{   
    // 계산한 나머지를 담을 변수와 a와 b의 값을 교환할 때 사용할 변수를 초기화합니다.
    uint16_t r = 0, temp;

    // 계산 할 때 a가 항상 b보다 작도록 합니다(무한 루프 방지). 
    if (a > b) {
        temp = a;
        a = b;
        b = temp;
    }
    // b가 0보다 클 동안 곱하기(XOR + shift)를 반복합니다.
    while (b > 0) {
        // coefficient가 1인 경우에만 XOR합니다.
        if (b & 1) {
            r = r ^ a;
        }
        // b를 왼쪽으로 한 칸 shift 합니다(곱셈 횟수 차감, 시간복잡도를 log 스케일로 줄일 수 있음).
        b = b >> 1;
        // 만약 a의 맨 왼쪽 비트가 존재하면(0x8000h = 1000 0000 0000 0000b)
        if (a & 0x8000) { 
            // a를 오른쪽으로 한 칸 shift하고 modulo reduction을 진행합니다(shift & XOR).
            // 0x1002B = 65579 = 2^16 + 2^5 + 2^3 + 2 + 1
            a = (a << 1) ^ 0x1002B;
        // modulo reduction이 필요하지 않을 경우
        } else {
            // a를 오른쪽으로 한 칸 shift합니다.
            a <<= 1; 
        }
        //a = ((a << 1) ^ ( (a >> 15) & 1 ? 0x1002B : 0)); // -> 함수 길이를 줄일 수 있지만 초심자는 이해하기 어려움.
    }
    // 계산된 나머지를 반환합니다.
    return r;
}

/*
 * gf16_pow(a,b) - a^b mod x^16+x^5+x^3+x+1
 *
 * 15차식 다항식 a를 b번 지수승한 결과를 16차식 x^16+x^5+x^3+x+1로 나눈 나머지를 계산한다.
 * gf16_mul()과 "Square Multiplication" 알고리즘을 사용하여 구현한다.
 */
uint16_t gf16_pow(uint16_t a, uint16_t b)
{   
    // modulo reduction은 gf16_mul 함수에서 대응가능합니다.
    // 나머지를 저장할 변수를 초기화합니다.
    uint16_t r = 1;

    // b가 0보다 클 동안 반복합니다.
    while (b > 0) {
        // coefficient가 1인 경우에만 나머지와 a를 곱합니다.
        if (b & 1) {
            r = gf16_mul(r, a);
        }
        // b를 왼쪽으로 한 칸 shift 합니다(곱셈 횟수 차감, 시간복잡도를 log 스케일로 줄일 수 있음).
        b = b >> 1;
        // coefficient가 0인 경우에만 a를 제곱합니다.
        a = gf16_mul(a, a);
    }
    // 나머지를 반환합니다.
    return r;   
}

/*
 * gf16_inv(a) - a^-1 mod x^16+x^5+x^3+x+1
 *
 * 모둘러 x^16+x^5+x^3+x+1에서 a의 역을 구한다.
 * 역을 구하는 가장 효율적인 방법은 다항식 확장유클리드 알고리즘을 사용하는 것이다.
 * 다만 여기서는 복잡성을 피하기 위해 느리지만 알기 쉬운 지수를 사용하여 구현하였다.
 */
uint16_t gf16_inv(uint16_t a)
{   
    // GF(p) is the set of integers {0, 1, ..., p-1} with arithmetic operations modulo prime p.
    // 윌슨의 정리 : p가 소수라면 1과 p - 1을 제외한 p보다 작은 정수들로 (p-3)/2 개의 정수의 쌍을 만들고, 각 쌍은 서로 역이 되는 정수가 되게 할 수 있다.
    // 페르마의 작은 정리 : p가 소수이고 a가 p로 나눌 수 없는 정수이면, a^(p-1) ≡ 1 (mod p)이다. 즉, if non-zero a ∈ GF(p), then a^(p-1) = 1.
    // 유한체에서는 다음과 같다 : If non-zero a ∈ GF(2^n), then a^(2^(n)-1) = 1. 즉, a^(-1) = a^(2^(n) - 2)
    return gf16_pow(a, 0xfffe);
}

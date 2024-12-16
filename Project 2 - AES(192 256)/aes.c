/*
 * Copyright(c) 2020-2024 All rights reserved by Heekuck Oh.
 * 이 프로그램은 한양대학교 ERICA 컴퓨터학부 학생을 위한 교육용으로 제작되었다.
 * 한양대학교 ERICA 학생이 아닌 자는 이 프로그램을 수정하거나 배포할 수 없다.
 * 프로그램을 수정할 경우 날짜, 학과, 학번, 이름, 수정 내용을 기록한다.
 */

/* By the grace of the Lord */

#include "aes.h"
#include <endian.h>
#include <string.h>

static const uint8_t sbox[256] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static const uint8_t isbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

static const uint8_t Rcon[11] = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

static const uint8_t M[16] = {2, 3, 1, 1, 1, 2, 3, 1, 1, 1, 2, 3, 3, 1, 1, 2};

static const uint8_t IM[16] = {0x0e, 0x0b, 0x0d, 0x09, 0x09, 0x0e, 0x0b, 0x0d, 0x0d, 0x09, 0x0e, 0x0b, 0x0b, 0x0d, 0x09, 0x0e};

/*
 * Generate an AES key schedule
 */
// 입력으로 받은 하나의 word(4byte)를 왼쪽으로 1byte 환형 shift합니다.
// 기존의 word를 왼쪽으로 1byte shift한 것과 오른쪽으로 3byte shift한 것을
// OR 연산으로 합치면 구할 수 있습니다. ex. [B0, B1, B2, B3] -> [B1, B2, B3, B0].
uint32_t RotWord(uint32_t temp) {
    return (temp << 8) | (temp >> 24);
  }

// 입력으로 받은 word를 1byte씩 구분하고 구분된 byte를 sbox를 조회하는 인덱스로 
// 사용하여 치환활 값을 구한 후 다시 하나의 word로 합쳐서 반환합니다.
// 교재나 FIPS-197 문서에서는 sbox 배열을 2차원으로 구성하여 구분된 byte를 row, column으로
// 분리할 필요가 있지만 본 과제에서는 sbox를 1차원 배열로 구성하였으므로 별도 계산 불필요합니다.
uint32_t SubWord(uint32_t temp) {
    uint32_t word = 0;
    word = (sbox[(temp >> 24) & 0xFF] << 24) | (sbox[(temp >> 16) & 0xFF] << 16) | (sbox[(temp >> 8) & 0xFF] << 8) | sbox[temp & 0xFF];
    return word;
}

// 입력으로 받은 키를 이용하여 roundKey를 생성합니다(키를 확장합니다).
void KeyExpansion(const uint8_t *key, uint32_t *roundKey, int length)
{ 
  int nr = Nr, nk = Nk;
  if (length == 1)
    nr = Nr_192, nk = Nk_192;
  else if (length == 2)
    nr = Nr_256, nk = Nk_256;
  // RotWord, SubWord 함수에 RoundKey를 전달하기 위한 변수를 초기화합니다.
  uint32_t temp;
  // 0라운드에서 사용할 roundKey(4 words)를 생성합니다. 기존에 입력받은 키를 세로로 한 줄(4byte)씩 읽어서
  // 하나로 합친 후 roundKey 배열에 저장합니다.
  int i = 0;
  while (i < nk) {
    roundKey[i] = (key[4*i] << 24) | (key[4*i+1] << 16) | (key[4*i+2] << 8) | key[4*i+3];
    i++;
  }
  // Nk(Number of 32-bit words comprising the Cipher Key)
  i = nk;
  // 총 10라운드에 사용할 키(40 words)를 생성합니다.
  while (i < Nb * (nr+1)) {
    // 계산에 사용하기 위해 전 단계의 roundKey를 변수에 저장합니다.
    temp = roundKey[i-1];
    // 생성해야할 word의 인덱스가 Nk로 나눠진다면
    if (i % nk == 0) {
      // 전번의 roundKey를 RotWord/SubWord 함수를 이용하여 전치, 치환한 후 round 상수 Rcon[i/Nk]과 XOR합니다.
      // Rcon[i/Nk]를 왼쪽으로 24bit shift(0x64000000 형식으로 변환)해야 올바른 계산 결과가 나옵니다.
      // Rcon[i] : contains the values given by [x^(i-1),{00},{00},{00}], with x^(i-1) being powers of x (x is denoted as {02}) in the field GF(2^8).
      temp = RotWord(SubWord(temp)) ^ (Rcon[i/nk] << 24);
      // AES-256을 위한 추가 치환 절차입니다.
    } else if (nk > 6 && i % nk == 4) {
      temp = SubWord(temp);
    }
    // 계산된 temp와 i-Nk전에 위치한 roundKey를 XOR하여 현 단계의 roundKey를 생성합니다.
    roundKey[i] = roundKey[i-nk] ^ temp;
    i++;
  }
  // 이렇게 생성된 roundKey는 test.c에 저장된 rKey와 동일하지만 endian 방식의 차이로 인해
  // test.c 실행 시 라운드 키가 불일치하다는 결과를 얻게됩니다. htobe32 함수를 사용하여 big-endian방식으로 전환합니다.
  if (__BYTE_ORDER == __LITTLE_ENDIAN) 
      for (int i = 0 ; i < Nb * (nr+1) ; i++) {
        roundKey[i] = htobe32(roundKey[i]);
      }
}

/*
 * AES cipher function
 * If mode is nonzero, then do encryption, otherwise do decryption.
 */

// roundKey를 state에 XOR하여 더합니다.
static void AddRoundKey(uint8_t *state, const uint32_t *roundKey, int start) {
  for (int i = 0 ; i < Nb ; i++) {
    // 입력으로 주어진 roundKey는 4개의 word로 구성되어 있으므로 계산을 쉽게 하기 위해
    // state(4 x 4 행렬로 가정)를 가로로 한 줄씩 읽어서 하나의 word로 만듭니다.
    // FIPS-197 문서에는 세로로 한 줄씩 읽어서 XOR하지만 이 방식은 추가로 RoundKey를 분할하여 
    // 세로로 재구성해야 하므로 번거롭습니다.
    uint32_t n_state = (state[Nb*i] << 24) | (state[Nb*i+1] << 16) | (state[Nb*i+2] << 8) | (state[Nb*i+3]);
    // 만들어진 n_state와 roundKey를 XOR 합니다. 이 때 라운드키는 빅 엔디안 방식으로 저장되어 있으므로
    // 다시 호스트 시스템에서 사용중인 엔디안 방식으로 변경해야 합니다.
    // start 변수를 이용하면 별도의 for 구문을 두지 않고도 roundKey를 조회할 수 있습니다.
    //printf("roundkey : %08x\n", roundKey[start + i]);
    n_state ^= be32toh(roundKey[start + i]);
    // 계산된 n_state를 shift 연산을 통해 1byte씩 분리하여 기존의 state에 저장합니다.
    state[Nb*i] = (n_state >> 24) & 0xFF;
    state[Nb*i+1] = (n_state >> 16) & 0xFF;
    state[Nb*i+2] = (n_state >> 8) & 0xFF;
    state[Nb*i+3] = n_state & 0xFF;
  }
} 

// sbox 또는 isbox를 이용하여 state를 치환합니다.
// SubWord 함수와 동일한 방식으로 조회하여 치환합니다.
// 반복횟수를 조금이라도 줄이기 위해 키를 4개씩 끊어서 조회하도록 구성하였습니다.
static void SubBytes(uint8_t *state, int mode) {
  // 모드가 ENCRYPT인 경우 sbox를 조회합니다.
  if (mode > 0) {
    for (int i = 0 ; i < 4 * Nb ; i += 4) {
      state[i] = sbox[state[i]];
      state[i+1] = sbox[state[i+1]];
      state[i+2] = sbox[state[i+2]];
      state[i+3] = sbox[state[i+3]];
    }
  // 모드가 DECRYPT인 경우 isbox를 조회합니다.
  } else {
    for (int i = 0 ; i < 4 * Nb ; i += 4) {
      state[i] = isbox[state[i]];
      state[i+1] = isbox[state[i+1]];
      state[i+2] = isbox[state[i+2]];
      state[i+3] = isbox[state[i+3]];
    }
  }
}

// state(4 x 4 행렬로 가정)의 첫번째 행(row)를 제외하고 나머지 행들을 규칙에 맞게 환형 shift합니다.
// state를 구성하는 input byte가 가로 순이 아니라 세로 순으로 저장되어 있다고 생각해야 합니다. 
// {0, 4, 8, 12} / {1, 5, 9, 13} / {2, 6, 10, 14} / {3, 7, 11, 15}
static void ShiftRows(uint8_t *state, int mode) {
  // 모드가 ENCRYPT인 경우
  if (mode > 0) {
    for (int i = 1 ; i < Nb ; i++) {
      // 계산을 쉽게 하기 위해 순서대로 하나의 word로 합칩니다.
      uint32_t n_state = (state[i] << 24) | (state[1*Nb+i] << 16) | (state[2*Nb+i] << 8) | (state[3*Nb+i]);
      // 왼쪽으로 1/2/3byte씩 환형 shift합니다.
      n_state = (n_state << i * 8) | (n_state >> (32 - i * 8));
      // 계산된 n_state를 shift 연산을 통해 1byte씩 분리하여 기존의 state에 저장합니다.
      state[i] = (n_state >> 24) & 0xFF;
      state[1*Nb+i] = (n_state >> 16) & 0xFF;
      state[2*Nb+i] = (n_state >> 8) & 0xFF;
      state[3*Nb+i] = n_state & 0xFF;
    }
  // 모드가 DECRYPT인 경우 
  } else {
    for (int i = 1 ; i < Nb ; i++) {
      // 계산을 쉽게 하기 위해 순서대로 하나의 word로 합칩니다.
      uint32_t n_state = (state[i]<< 24) | (state[1*Nb+i] << 16) | (state[2*Nb+i] << 8) | (state[3*Nb+i]);
      // 오른쪽으로 1/2/3byte씩 환형 shift합니다.
      n_state = (n_state >> i * 8) | (n_state << (32 - i * 8));
      // 계산된 n_state를 shift 연산을 통해 1byte씩 분리하여 기존의 state에 저장합니다.
      state[i] = (n_state >> 24) & 0xFF;
      state[1*Nb+i] = (n_state >> 16) & 0xFF;
      state[2*Nb+i] = (n_state >> 8) & 0xFF;
      state[3*Nb+i] = n_state & 0xFF;
    }
  }
}

// 주어진 두 수 a, b를 곱하고 결과를 기약 다항식 𝑥^8 + 𝑥^4 + 𝑥^3 + 𝑥 + 1로 나눈 나머지를 구합니다.
// MixColums 함수에서 사용됩니다.
uint8_t gf8_mul(uint8_t a, uint8_t b)
{   
    // 계산한 나머지를 담을 변수를 초기화합니다.
    uint8_t r = 0;

    // b가 0보다 클 동안 곱하기(XOR + shift)를 반복합니다.
    while (b > 0) {
        // coefficient가 1인 경우에만 XOR합니다.
        if (b & 1) 
            r = r ^ a;
        // b를 왼쪽으로 한 칸 shift 합니다(곱셈 횟수 차감, 시간복잡도를 log 스케일로 줄일 수 있음).
        b = b >> 1;
        a = XTIME(a);
    }
    // 계산된 나머지를 반환합니다.
    return r;
}

// 기약 다항식 𝑥^8 + 𝑥^4 + 𝑥^3 + 𝑥 + 1을 사용한 GF(2^8)에서 행렬곱셈을 수행합니다.
static void MixColumns(uint8_t *state, int mode) {
  // state를 그대로 사용하면 계산 중 값이 변동되므로 계산을 위해 t_state라는 변수를 새로 만들고 state의 값을 t_state에 저장합니다. 
  uint8_t t_state[BLOCKLEN];
  memcpy(t_state, state, BLOCKLEN);
  // 모드가 ENCRYPT인 경우
  if (mode > 0) {
    // state(4 x 4 행렬로 가정)를 세로로 한 줄씩 읽어서 각 byte를 gf8_mul 함수를 이용하여 M[16]의 원소들과 차례대로 곱한 후 XOR 해줍니다.
    for (int i = 0 ; i < Nb; i++) {
      state[Nb*i+0] = gf8_mul(t_state[Nb*i+0], M[0]) ^ gf8_mul(t_state[Nb*i+1], M[1]) ^ t_state[Nb*i+2] ^ t_state[Nb*i+3];
      state[Nb*i+1] = t_state[Nb*i+0] ^ gf8_mul(t_state[Nb*i+1], M[5]) ^ gf8_mul(t_state[Nb*i+2], M[6]) ^ t_state[Nb*i+3];
      state[Nb*i+2] = t_state[Nb*i+0] ^ t_state[Nb*i+1] ^ gf8_mul(t_state[Nb*i+2], M[10]) ^ gf8_mul(t_state[Nb*i+3], M[11]);
      state[Nb*i+3] = gf8_mul(t_state[Nb*i+0], M[12]) ^ t_state[Nb*i+1] ^ t_state[Nb*i+2] ^ gf8_mul(t_state[Nb*i+3], M[15]);
    }
  // 모드가 DECRYPT인 경우
  } else {
    // state(4 x 4 행렬로 가정)를 세로로 한 줄씩 읽어서 각 byte를 gf8_mul 함수를 이용하여 IM[16]의 원소들과 차례대로 곱한 후 XOR 해줍니다.
    for (int i = 0 ; i < Nb; i++) {
      state[Nb*i+0] = gf8_mul(t_state[Nb*i+0], IM[0]) ^ gf8_mul(t_state[Nb*i+1], IM[1]) ^ gf8_mul(t_state[Nb*i+2], IM[2]) ^ gf8_mul(t_state[Nb*i+3], IM[3]);
      state[Nb*i+1] = gf8_mul(t_state[Nb*i+0], IM[4]) ^ gf8_mul(t_state[Nb*i+1], IM[5]) ^ gf8_mul(t_state[Nb*i+2], IM[6]) ^ gf8_mul(t_state[Nb*i+3], IM[7]);
      state[Nb*i+2] = gf8_mul(t_state[Nb*i+0], IM[8]) ^ gf8_mul(t_state[Nb*i+1], IM[9]) ^ gf8_mul(t_state[Nb*i+2], IM[10]) ^ gf8_mul(t_state[Nb*i+3], IM[11]);
      state[Nb*i+3] = gf8_mul(t_state[Nb*i+0], IM[12]) ^ gf8_mul(t_state[Nb*i+1], IM[13]) ^ gf8_mul(t_state[Nb*i+2], IM[14]) ^ gf8_mul(t_state[Nb*i+3], IM[15]);
    }
  }
}


// 크기가 16바이트인 state를 roundKey를 사용하여 암복호화합니다.
// 이때 mode가 ENCRYPT이면 암호화를 수행하고 DECRYPT이면 복호화를 수행합니다.
void Cipher(uint8_t *state, const uint32_t *roundKey, int mode, int length)
{
  int nr = Nr;
  if (length == 1)
    nr = Nr_192;
  else if (length == 2)
    nr = Nr_256;
  // 모드가 ENCRYPT인 경우
  if (mode > 0) {
      // State에 첫 번째 라운드키 묶음을 더합니다.
      AddRoundKey(state, roundKey, 0);
      // 총 Nr-1회 동안 암호화 작업을 진행합니다.
      // AddRoundKey 함수에는 i * Nb를 전달해서 유효한 라운드키 묶음이 전달되도록 합니다.
      for (int i = 1 ; i < nr; i++) {
        SubBytes(state, mode);
        ShiftRows(state, mode);
        MixColumns(state, mode);
        AddRoundKey(state, roundKey, i * Nb);
      }
      // 마지막 라운드에서는 MixColums를 진행하지 않습니다.
      SubBytes(state, mode);
      ShiftRows(state, mode);
      AddRoundKey(state, roundKey, nr * Nb);
  // 모드가 DECRYPT인 경우
  } else {
    // State에 마지막 라운드키 묶음을 더합니다.
    AddRoundKey(state, roundKey, nr * Nb);
    // 총 Nr-1회 동안 암호화 작업을 진행합니다.
    // 암호화와는 달리 shiftRows를 먼저 진행하고 SubBytes를 진행합니다.
    // AddRoundKey 함수에는 i * Nb를 전달해서 유효한 라운드키 묶음이 전달되도록 합니다.
    for (int i = nr-1 ; i > 0; i--) {
      ShiftRows(state, mode);
      SubBytes(state, mode);
      AddRoundKey(state, roundKey, i * Nb);
      MixColumns(state, mode);
    }
    // 마지막 라운드에서는 MixColums를 진행하지 않습니다.
    ShiftRows(state, mode);
    SubBytes(state, mode);
    AddRoundKey(state, roundKey, 0);
  }
}
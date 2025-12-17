---
title: re加密算法总结
date: 2025-12-17
tags: [加密]
category: CTF
published: 2025-11-27
description: 自己写的re常见加解密算法，融入个人理解，长期更新
---

# 加密算法

## 00 BASEXX

**识别出来后把表找到建议直接cyberchef；**

代码差不多这样，只演示了base64的一次编码（直接移位）；

```cpp
#include <string>
#include <vector>

static const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

std::string base64_encode(const std::vector<uint8_t>& data) {
    std::string out;
    size_t i = 0;
    while (i < data.size()) {
        // 每次取 3 字节
        uint32_t buf = 0;
        int bytes = 0;
        for (; bytes < 3 && i < data.size(); ++bytes, ++i) {
            buf <<= 8;
            buf |= data[i];
        }
        buf <<= (3 - bytes) * 8; // 不足时补 0

        // 拆成 4 个 6 位
        for (int j = 0; j < 4; ++j) {
            if (j <= (bytes)) {
                out.push_back(base64_chars[(buf >> (18 - 6*j)) & 0x3F]);
            } else {
                out.push_back('='); // 填充
            }
        }
    }
    return out;
}
```

base58（转大整数取模）：

```cpp
#include <string>
#include <vector>

static const std::string base58_chars =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

std::string base58_encode(const std::vector<uint8_t>& data) {
    // 大整数用 vector<int> 表示，每个元素是“进制 58”的一位
    std::vector<int> digits(1, 0);

for (uint8_t byte : data) {
    int carry = byte;
    for (size_t i = 0; i < digits.size(); ++i) {
        int val = digits[i] * 256 + carry;
        digits[i] = val % 58;
        carry = val / 58;
    }
    while (carry > 0) {
        digits.push_back(carry % 58);
        carry /= 58;
    }
}

// 处理前导零：每个 0 字节对应一个 '1'
std::string out;
for (uint8_t byte : data) {
    if (byte == 0) out.push_back('1');
    else break;
}

// digits 是低位在前，需要反转
for (auto it = digits.rbegin(); it != digits.rend(); ++it) {
    out.push_back(base58_chars[*it]);
}

return out;
```



## 01 RC4

RC4属于对称密码中的流密码，先使用key生成一个密钥流，再与明文异或得到密文；

**因为对称，最理想的解决办法是将密文弄出来patch进输入，密钥流不管，找到最后判断位置的加密后的文字就行（就是明文）**；

```cpp
#include<iostream>
#include<stdint.h>
#include<string>
#include<vector>                                                             
using namespace std;
uint8_t s[256];
uint8_t k[256];
string key = "wes1meanon";    
string ori = "abcdef123456";  //plain
vector<uint8_t> src = {};   //cipher
//string src = "";

void init_table()
{
  for (int i = 0; i <= 255; i++)
  {
     s[i] = i;        //初始化填充s盒,256字节线性填充
  }
  for (int j = 0; j <= 255; j++)
  {
​    k[j] = key[j % key.length()];   //初始化填充s盒,256字节,key字符串顺序填入
  }
  uint8_t x = 0;
  for (int l = 0; l <= 255; l++)
  {
​    x = (x + s[l] + k[l]) % 256;   //用k表对s表初始替换
​    swap (s[l], s[x]);
  }
}
vector<uint8_t> key_stream;       //获取密钥流

void get_stream()
{
  int stream_length = ori.length();  //长度与明文一致
  int i = 0;
  int j = 0;
  while(stream_length--)
  {
​    i = (i + 1) % 256;
​    j = (j + s[i]) % 256;
​    swap (s[i], s[j]);        //PRGA交换
​    uint8_t new_key = s[(s[i] + s[j]) % 256];  //逐字节生成
​    key_stream.push_back(new_key);
  }
}

void rc4_init()
{
  init_table();
  get_stream();
}

string rc4_encrypt()
{
  src.resize(ori.length());  // 分配空间
  string cipher;        // 保存密文
  for (int i = 0; i < ori.length(); i++)
  {
    unsigned char temp_src = key_stream[i] ^ ori[i];
    src[i] = temp_src;
    cipher.push_back(temp_src);   // 保存到密文
  }
  return cipher;
}

string rc4_decrypt()
{
  string plain;
  for (int i = 0; i < ori.length(); i++)
  {
    unsigned char temp_ori = key_stream[i] ^ src[i];
    plain.push_back(temp_ori);    // 保存到明文
  }
  return plain;
}

int main()
{
  rc4_init();
    
  string cipher = rc4_encrypt();
  cout << "Cipher (as numbers): ";
  for (unsigned char c : cipher)
    cout << (int)c << " ";
  cout << endl;
    
  string plain = rc4_decrypt();
  cout << "Plain: " << plain << endl;
  return 0;
}
```

## 02  TEA

明文一定是8字节，key16字节，块加密32轮；

**直接逆就行，异或的一块不用管，注意魔数，轮数，位移数等各种地方都容易被改；**

```cpp
#include <iostream>
#include <cstdint>
#include <cstring>
#include <vector>
using namespace std;

// TEA 加密函数：对一个 64-bit（两个 uint32_t）块进行加密
void TEA_encrypt(uint32_t* v, const uint32_t* key) {
  uint32_t v0 = v[0], v1 = v[1];     // 拆分为两个 32-bit 的部分
  uint32_t sum = 0;
  const uint32_t delta = 0x9e3779b9;   // 一个常用的“魔数”，用于扰乱加密过程
  // TEA 进行 32 轮加密
  for (int i = 0; i < 32; ++i) {
    sum += delta;
    v0 += ((v1 << 4) + key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key[1]);
    v1 += ((v0 << 4) + key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key[3]);
  }
  v[0] = v0;
  v[1] = v1;
}

// TEA 解密函数：对一个 64-bit 块进行解密
void TEA_decrypt(uint32_t* v, const uint32_t* key) {
  uint32_t v0 = v[0], v1 = v[1];
  const uint32_t delta = 0x9e3779b9;
  uint32_t sum = delta * 32;  // 初始 sum 是加密时累加的最终值
  // TEA 进行 32 轮解密（加密的逆过程）
  for (int i = 0; i < 32; ++i) {
    v1 -= ((v0 << 4) + key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key[3]);
    v0 -= ((v1 << 4) + key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key[1]);
    sum -= delta;
  }
  v[0] = v0;
  v[1] = v1;
}

int main() {
  // cipher = ;
  // uint32_t key[4] = {} ;
  // for (int i = 0; i < ; i++)
  //   TEA_decrypt (cipher+2*i, key) ;
  // for (int i = 0 ;i < ; i++)
  //   cout << *((char*)cipher+i) ;
  return 0;
}
```

## 03 XTEA

就是比TEA多了一个选key的步骤；通过 `sum & 3` 和 `(sum >> 11) & 3` 选择 key 的不同部分，使每轮使用的密钥更加多样。

一样直接反着逆；

> ### XTEA 与 TEA 的区别
>
> | 特性       | TEA                   | XTEA                            |
> | ---------- | --------------------- | ------------------------------- |
> | 轮数       | 32                    | 64                              |
> | 密钥调度   | 固定顺序使用 key[0~3] | 使用 `sum` 的位运算动态选择 key |
> | 安全性     | 存在相关密钥攻击风险  | 更安全，抵抗已知的 TEA 弱点     |
> | 实现复杂度 | 简单                  | 稍复杂，但仍然轻量              |

```cpp
#include <iostream>
#include <cstdint>
#include <cstring>
#include <vector>
using namespace std;

void XTEA_encrypt(uint32_t* v, const uint32_t* key) {
    uint32_t v0 = v[0], v1 = v[1];
    uint32_t sum = 0;
    const uint32_t delta = 0x9E3779B9;

    for (int i = 0; i < 64; ++i) {
        uint32_t k = key[sum & 3];  // 使用 sum 的低 2 位选择 key 的索引
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k);
        sum += delta;
        k = key[(sum >> 11) & 3];  // 使用 sum 的高位选择另一个 key 索引
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k);
    }
    v[0] = v0;
    v[1] = v1;
}

void XTEA_encrypt(uint32_t* v, const uint32_t* key) {
    uint32_t v0 = v[0], v1 = v[1];
    uint32_t sum = 0;
    const uint32_t delta = 0x9E3779B9;

    for (int i = 0; i < 64; ++i) {
        uint32_t k = key[sum & 3];  // 使用 sum 的低 2 位选择 key 的索引
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k);
        sum += delta;
        k = key[(sum >> 11) & 3];  // 使用 sum 的高位选择另一个 key 索引
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k);
    }
    v[0] = v0;
    v[1] = v1;
}

int main() {
  // cipher = ;
  // uint32_t key[4] = {} ;
  // for (int i = 0; i < ; i++)
  //   TEA_decrypt (cipher+2*i, key) ;
  // for (int i = 0 ;i < ; i++)
  //   cout << *((char*)cipher+i) ;
  return 0;
}

```

  ## 04 XXTEA

改动有点大的xtea，但本质还是那个逻辑，一样反着逆就行；

原文字节无要求，密钥依然是16位；

```cpp
#include <cstdint>
#include <vector>
#include <array>

// XXTEA 加密
void xxtea_encrypt(std::vector<uint32_t>& v, const std::array<uint32_t,4>& k) {
    const uint32_t DELTA = 0x9E3779B9;
    size_t n = v.size();
    if (n < 2) return; // 至少两个元素

    uint32_t sum = 0;
    uint32_t q = 6 + 52 / n;   //轮数
    uint32_t z = v[n-1], y;		//其中 y 是下一个元素，z 是上一个更新过的元素。

    while (q-- > 0) {
        sum += DELTA;
        uint32_t e = (sum >> 2) & 3;
        for (size_t p = 0; p < n-1; ++p) {
            y = v[p+1];	
            uint32_t kpe = k[(p ^ e) & 3];  //key
            // 核心混合公式
            v[p] += (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (kpe ^ z));
            z = v[p];	//其中 y 是下一个元素，z 是上一个更新过的元素。
        }
        y = v[0];  //最后一轮
        uint32_t kpe_last = k[((n-1) ^ e) & 3];
        v[n-1] += (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (kpe_last ^ z));
        z = v[n-1];
    }
}

void xxtea_decrypt(uint32_t* v, size_t n, const uint32_t* k) {
    const uint32_t DELTA = 0x9E3779B9;
    uint32_t rounds = 6 + 52 / n;
    uint32_t sum = rounds * DELTA;
    uint32_t y, z;  
    
    y = v[0];  
    while (rounds--) {
        uint32_t e = (sum >> 2) & 3;
        for (unsigned p = (unsigned)n - 1; p > 0; --p) {
            z = v[p - 1];
            y = v[p] -= (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))
                         ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z));
        }
        z = v[n - 1];
        y = v[0] -= (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))
                     ^ ((sum ^ y) + (k[(0 & 3) ^ e] ^ z));
        sum -= DELTA;
    }
}


int main() {
//示例板子使用
uint32_t data[10] = {
    0xCC777935, 0x3441131B, 0x919FFFF9, 0x78945BFF,
    0xAEAF2A86, 0x4D319ED7, 0x51A5C47A, 0x446ED9D1,
    0x1B865218, 0x63C98A42
};
uint8_t key[17] = "2048master2048ma";

xxtea_decrypt(data, 10, (uint32_t*)key);

for (int i = 0; i < sizeof(data)/sizeof(data[0])*4; ++i) {
    std::cout << *(uint8_t*)((uint8_t*)data + i);
}
std::cout << std::endl;
}

```

*下面AI写的文字逻辑：*

> 1. **准备数据**
>
>    - 把明文分成若干个 32 位无符号整数（至少两个），组成数组 `v[0..n-1]`。
>    - 准备 128 位密钥 `k[0..3]`。
>    - 设置常量 `DELTA = 0x9E3779B9`。
>
> 2. **确定轮数**
>
>    - 轮数 `q = 6 + 52/n`，其中 `n` 是数组长度。
>    - 这是为了保证足够的混合扩散。
>
> 3. **循环加密**
>
>    - 初始化 `sum = 0`。
>
>    - 每一轮：
>
>      - `sum += DELTA`。
>
>      - 计算 `e = (sum >> 2) & 3`。
>
>      - 遍历数组：
>
>        - 对每个元素 `v[p]`，使用它的相邻元素（`v[p+1]` 或最后一个用 `v[0]`）和密钥 `k[(p ^ e) & 3]`，通过移位、异或、加法混合更新。
>
>        - 更新公式大致是：
>
>          ```
>          v[p] += ((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (k[...] ^ z))
>          ```
>
>          其中 `y` 是下一个元素，`z` 是上一个更新过的元素。
>
>    - 重复直到完成所有轮次。
>
> ### DECRYPT:
>
> 1. **准备数据**
>
>    - 同样是数组 `v[0..n-1]` 和密钥 `k[0..3]`。
>    - 常量 `DELTA = 0x9E3779B9`。
>
> 2. **确定轮数**
>
>    - `q = 6 + 52/n`。
>    - 初始化 `sum = q * DELTA`。
>
> 3. **循环解密**
>
>    - 每一轮：
>
>      - 计算 `e = (sum >> 2) & 3`。
>
>      - 倒序遍历数组：
>
>        - 对每个元素 `v[p]`，使用它的前一个元素（`v[p-1]`，第一个用 `v[n-1]`）和密钥 `k[(p ^ e) & 3]`，通过同样的混合公式来 **减去** 加密时的操作。
>
>        - 更新公式大致是：
>
>          ```
>          v[p] -= ((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (k[...] ^ z))
>          ```
>
>    - 每轮结束后 `sum -= DELTA`，直到 `sum = 0`。
>
> ### SUMMARY:
>
> - **加密**：从 `sum=0` 开始，每轮加 `DELTA`，正向遍历数组，做“加法更新”。
> - **解密**：从 `sum=q*DELTA` 开始，每轮减 `DELTA`，反向遍历数组，做“减法更新”。
> - **特征**：大量的移位（>>5, <<2, >>3, <<4）、异或、加法混合；环状使用相邻元素；常量 `0x9E3779B9` 很容易在逆向时识别。

## 05 DES

DES有两个输入，分别是**分组长度为64位的明文**，和**长度为56位的密钥**（实际为64位，剩下的8位可以作为奇偶校验码或随意设置），**输出64位的密文**。

加密过程简单为：**初始盒置换+feistel加密16轮+逆初始盒置换**。

```c++
// 对 64 位数据块做 DES 加密（单块）
uint64_t des_encrypt_block(uint64_t plaintext, uint64_t key) {
    // 1. 初始置换 IP
    uint64_t ip = permute(plaintext, IP, 64, 64);

    // 拆成 L0, R0 每 32 位
    uint32_t L = (uint32_t)(ip >> 32);
    uint32_t R = (uint32_t)(ip & 0xFFFFFFFF);

    // 2. 生成 16 轮子密钥
    uint64_t round_keys[16];
    generate_round_keys(key, round_keys);

    // 3. 16 轮 Feistel
    for (int i = 0; i < 16; ++i) {
        uint32_t oldL = L;
        uint32_t oldR = R;

        L = oldR;
        R = oldL ^ feistel_F(oldR, round_keys[i]);
    }

    // 4. 最后一轮结束后，交换 L16 和 R16 顺序（R16 在左）
    uint64_t preoutput = ((uint64_t)R << 32) | L;

    // 5. 逆初始置换 IP^-1
    uint64_t ciphertext = permute(preoutput, IP_INV, 64, 64);
    return ciphertext;
}
```

完整加解密实现：

```cpp
#include <iostream>
#include <cstdint>
using namespace std;

// ===== 各类表（与前一份代码完全相同） =====

static const int IP[64] = {
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7
};

static const int IP_INV[64] = {
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25
};

static const int PC1[56] = {
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
};

static const int PC2[48] = {
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

static const int SHIFTS[16] = {
    1, 1, 2, 2,
    2, 2, 2, 2,
    1, 2, 2, 2,
    2, 2, 2, 1
};

static const int E[48] = {
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
};

static const int SBOX[8][4][16] = {
    {
        {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
        {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
        {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
        {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
    },
    {
        {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
        {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
        {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
        {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
    },
    {
        {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
        {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
        {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
        {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
    },
    {
        {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
        {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
        {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
        {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
    },
    {
        {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
        {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
        {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
        {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
    },
    {
        {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
        {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
        {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
        {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
    },
    {
        {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
        {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
        {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
        {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
    },
    {
        {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
        {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
        {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
        {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
    }
};

static const int P[32] = {
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
};

// ===== 通用函数 =====

uint64_t permute(uint64_t input, const int *table, int output_len, int input_len = 64) {
    uint64_t output = 0;
    for (int i = 0; i < output_len; ++i) {
        int from = table[i];
        int shift = input_len - from;
        uint64_t bit = (input >> shift) & 1ULL;
        output = (output << 1) | bit;
    }
    return output;
}

uint32_t left_rotate28(uint32_t v, int n) {
    v &= 0x0FFFFFFF;
    return ((v << n) | (v >> (28 - n))) & 0x0FFFFFFF;
}

void generate_round_keys(uint64_t key, uint64_t round_keys[16]) {
    uint64_t key56 = permute(key, PC1, 56, 64);
    uint32_t C = (key56 >> 28) & 0x0FFFFFFF;
    uint32_t D = key56 & 0x0FFFFFFF;

    for (int i = 0; i < 16; ++i) {
        C = left_rotate28(C, SHIFTS[i]);
        D = left_rotate28(D, SHIFTS[i]);
        uint64_t CD = ((uint64_t)C << 28) | D;
        round_keys[i] = permute(CD, PC2, 48, 56);
    }
}

uint64_t expand_E(uint32_t R) {
    return permute((uint64_t)R << 32, E, 48, 64);
}

uint32_t sbox_substitution(uint64_t x) {
    uint32_t output = 0;
    for (int i = 0; i < 8; ++i) {
        int shift = (7 - i) * 6;
        uint8_t six = (x >> shift) & 0x3F;
        int row = ((six & 0x20) >> 4) | (six & 0x01);
        int col = (six >> 1) & 0x0F;
        uint8_t s_val = SBOX[i][row][col];
        output = (output << 4) | s_val;
    }
    return output;
}

uint32_t feistel_F(uint32_t R, uint64_t K) {
    uint64_t ER = expand_E(R);
    uint64_t x = ER ^ K;
    uint32_t s_out = sbox_substitution(x);
    uint32_t f_out = (uint32_t)permute((uint64_t)s_out << 32, P, 32, 64);
    return f_out;
}

// ===== 加密：单块 =====

uint64_t des_encrypt_block(uint64_t plaintext, uint64_t key) {
    uint64_t ip = permute(plaintext, IP, 64, 64);
    uint32_t L = (uint32_t)(ip >> 32);
    uint32_t R = (uint32_t)(ip & 0xFFFFFFFF);

    uint64_t round_keys[16];
    generate_round_keys(key, round_keys);

    for (int i = 0; i < 16; ++i) {
        uint32_t oldL = L;
        uint32_t oldR = R;
        L = oldR;
        R = oldL ^ feistel_F(oldR, round_keys[i]);
    }

    uint64_t preoutput = ((uint64_t)R << 32) | L;
    uint64_t ciphertext = permute(preoutput, IP_INV, 64, 64);
    return ciphertext;
}

// ===== 解密：单块 =====

uint64_t des_decrypt_block(uint64_t ciphertext, uint64_t key) {
    // 1. IP 置换
    uint64_t ip = permute(ciphertext, IP, 64, 64);
    uint32_t L = (uint32_t)(ip >> 32);
    uint32_t R = (uint32_t)(ip & 0xFFFFFFFF);

    // 2. 生成 16 轮子密钥
    uint64_t round_keys[16];
    generate_round_keys(key, round_keys);

    // 3. 16 轮，但子密钥顺序反过来用
    for (int i = 15; i >= 0; --i) {
        uint32_t oldL = L;
        uint32_t oldR = R;
        L = oldR;
        R = oldL ^ feistel_F(oldR, round_keys[i]);
    }

    // 4. 最后同样交换 L、R，再做 IP^-1
    uint64_t preoutput = ((uint64_t)R << 32) | L;
    uint64_t plaintext = permute(preoutput, IP_INV, 64, 64);
    return plaintext;
}

// 简单测试
int main() {
    uint64_t plaintext = 0x0123456789ABCDEF;
    uint64_t key       = 0x133457799BBCDFF1;

    uint64_t ciphertext = des_encrypt_block(plaintext, key);
    uint64_t decrypted  = des_decrypt_block(ciphertext, key);

    cout << hex << uppercase;
    cout << "Plaintext : " << plaintext  << endl;
    cout << "Key       : " << key        << endl;
    cout << "Ciphertext: " << ciphertext << endl;
    cout << "Decrypted : " << decrypted  << endl;

    return 0;
}
```

因为和tea相似都是中间都是feistel块加密，所以直接一样逆着解就好；

初始表和逆初始表互逆，解密也是先对密文置换初始表，15轮->0轮feistal解密，置换逆初始表即可。

唯一差异：

- 加密：轮密钥 `round_keys[0] -> round_keys[15]`
- 解密：轮密钥 `round_keys[15] -> round_keys[0]`

CTF中可能会**改 S 盒 / 改置换表 / 改轮数**；

板子：

```cpp
#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <string>
#include <cstdint>
using namespace std;

// ========== 前面：DES 所需表，与之前完全相同 ==========

static const int IP[64] = {
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7
};

static const int IP_INV[64] = {
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25
};

static const int PC1[56] = {
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
};

static const int PC2[48] = {
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

static const int SHIFTS[16] = {
    1, 1, 2, 2,
    2, 2, 2, 2,
    1, 2, 2, 2,
    2, 2, 2, 1
};

static const int E[48] = {
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
};

static const int SBOX[8][4][16] = {
    {
        {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
        {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
        {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
        {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
    },
    {
        {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
        {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
        {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
        {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
    },
    {
        {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
        {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
        {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
        {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
    },
    {
        {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
        {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
        {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
        {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
    },
    {
        {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
        {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
        {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
        {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
    },
    {
        {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
        {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
        {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
        {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
    },
    {
        {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
        {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
        {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
        {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
    },
    {
        {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
        {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
        {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
        {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
    }
};

static const int P[32] = {
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
};

// ========== DES 基础函数 ==========

uint64_t permute(uint64_t input, const int *table, int output_len, int input_len = 64) {
    uint64_t output = 0;
    for (int i = 0; i < output_len; ++i) {
        int from = table[i];
        int shift = input_len - from;
        uint64_t bit = (input >> shift) & 1ULL;
        output = (output << 1) | bit;
    }
    return output;
}

uint32_t left_rotate28(uint32_t v, int n) {
    v &= 0x0FFFFFFF;
    return ((v << n) | (v >> (28 - n))) & 0x0FFFFFFF;
}

void generate_round_keys(uint64_t key, uint64_t round_keys[16]) {
    uint64_t key56 = permute(key, PC1, 56, 64);
    uint32_t C = (key56 >> 28) & 0x0FFFFFFF;
    uint32_t D = key56 & 0x0FFFFFFF;

    for (int i = 0; i < 16; ++i) {
        C = left_rotate28(C, SHIFTS[i]);
        D = left_rotate28(D, SHIFTS[i]);
        uint64_t CD = ((uint64_t)C << 28) | D;
        round_keys[i] = permute(CD, PC2, 48, 56);
    }
}

uint64_t expand_E(uint32_t R) {
    return permute((uint64_t)R << 32, E, 48, 64);
}

uint32_t sbox_substitution(uint64_t x) {
    uint32_t output = 0;
    for (int i = 0; i < 8; ++i) {
        int shift = (7 - i) * 6;
        uint8_t six = (x >> shift) & 0x3F;
        int row = ((six & 0x20) >> 4) | (six & 0x01);
        int col = (six >> 1) & 0x0F;
        uint8_t s_val = SBOX[i][row][col];
        output = (output << 4) | s_val;
    }
    return output;
}

uint32_t feistel_F(uint32_t R, uint64_t K) {
    uint64_t ER = expand_E(R);
    uint64_t x = ER ^ K;
    uint32_t s_out = sbox_substitution(x);
    uint32_t f_out = (uint32_t)permute((uint64_t)s_out << 32, P, 32, 64);
    return f_out;
}

uint64_t des_encrypt_block(uint64_t plaintext, uint64_t key) {
    uint64_t ip = permute(plaintext, IP, 64, 64);
    uint32_t L = (uint32_t)(ip >> 32);
    uint32_t R = (uint32_t)(ip & 0xFFFFFFFF);

    uint64_t round_keys[16];
    generate_round_keys(key, round_keys);

    for (int i = 0; i < 16; ++i) {
        uint32_t oldL = L;
        uint32_t oldR = R;
        L = oldR;
        R = oldL ^ feistel_F(oldR, round_keys[i]);
    }

    uint64_t preoutput = ((uint64_t)R << 32) | L;
    uint64_t ciphertext = permute(preoutput, IP_INV, 64, 64);
    return ciphertext;
}

uint64_t des_decrypt_block(uint64_t ciphertext, uint64_t key) {
    uint64_t ip = permute(ciphertext, IP, 64, 64);
    uint32_t L = (uint32_t)(ip >> 32);
    uint32_t R = (uint32_t)(ip & 0xFFFFFFFF);

    uint64_t round_keys[16];
    generate_round_keys(key, round_keys);

    for (int i = 15; i >= 0; --i) {
        uint32_t oldL = L;
        uint32_t oldR = R;
        L = oldR;
        R = oldL ^ feistel_F(oldR, round_keys[i]);
    }

    uint64_t preoutput = ((uint64_t)R << 32) | L;
    uint64_t plaintext = permute(preoutput, IP_INV, 64, 64);
    return plaintext;
}

// ========== 工具函数：字节 <-> uint64_t，hex 编解码 ==========

// bytes[8] -> uint64_t（大端）
uint64_t bytes_to_uint64(const uint8_t b[8]) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = (v << 8) | b[i];
    }
    return v;
}

// uint64_t -> bytes[8]（大端）
void uint64_to_bytes(uint64_t v, uint8_t b[8]) {
    for (int i = 7; i >= 0; --i) {
        b[i] = (uint8_t)(v & 0xFF);
        v >>= 8;
    }
}

// 字符串 -> bytes 向量
vector<uint8_t> string_to_bytes(const string &s) {
    return vector<uint8_t>(s.begin(), s.end());
}

// bytes 向量 -> 字符串
string bytes_to_string(const vector<uint8_t> &data) {
    return string(data.begin(), data.end());
}

// bytes -> hex 字符串
string bytes_to_hex(const vector<uint8_t> &data) {
    stringstream ss;
    ss << hex << uppercase << setfill('0');
    for (uint8_t b : data) {
        ss << setw(2) << (int)b;
    }
    return ss.str();
}

// hex 字符串 -> bytes
vector<uint8_t> hex_to_bytes(const string &hex) {
    vector<uint8_t> out;
    if (hex.size() % 2 != 0) return out;
    for (size_t i = 0; i < hex.size(); i += 2) {
        string byteStr = hex.substr(i, 2);
        uint8_t b = (uint8_t)strtol(byteStr.c_str(), nullptr, 16);
        out.push_back(b);
    }
    return out;
}

// ========== PKCS#7 填充 ==========

void pkcs7_pad(vector<uint8_t> &data, size_t blockSize) {
    size_t len = data.size();
    size_t pad = blockSize - (len % blockSize);
    if (pad == 0) pad = blockSize;
    for (size_t i = 0; i < pad; ++i) {
        data.push_back((uint8_t)pad);
    }
}

bool pkcs7_unpad(vector<uint8_t> &data, size_t blockSize) {
    if (data.empty() || data.size() % blockSize != 0) return false;
    uint8_t pad = data.back();
    if (pad == 0 || pad > blockSize) return false;
    if (data.size() < pad) return false;
    for (size_t i = 0; i < pad; ++i) {
        if (data[data.size() - 1 - i] != pad) return false;
    }
    data.resize(data.size() - pad);
    return true;
}

// ========== ECB 模式：多块加解密 ==========

vector<uint8_t> des_ecb_encrypt_bytes(const vector<uint8_t> &plaintextBytes, uint64_t key) {
    const size_t blockSize = 8;
    vector<uint8_t> data = plaintextBytes;
    pkcs7_pad(data, blockSize);

    vector<uint8_t> out;
    out.resize(data.size());

    uint64_t block;
    uint8_t buf[8];

    for (size_t offset = 0; offset < data.size(); offset += blockSize) {
        block = bytes_to_uint64(&data[offset]);
        uint64_t enc = des_encrypt_block(block, key);
        uint64_to_bytes(enc, buf);
        for (size_t i = 0; i < blockSize; ++i) {
            out[offset + i] = buf[i];
        }
    }
    return out;
}

vector<uint8_t> des_ecb_decrypt_bytes(const vector<uint8_t> &cipherBytes, uint64_t key) {
    const size_t blockSize = 8;
    if (cipherBytes.size() % blockSize != 0) {
        // 非整块，按出错处理，返回空
        return {};
    }

    vector<uint8_t> out;
    out.resize(cipherBytes.size());

    uint64_t block;
    uint8_t buf[8];

    for (size_t offset = 0; offset < cipherBytes.size(); offset += blockSize) {
        block = bytes_to_uint64(&cipherBytes[offset]);
        uint64_t dec = des_decrypt_block(block, key);
        uint64_to_bytes(dec, buf);
        for (size_t i = 0; i < blockSize; ++i) {
            out[offset + i] = buf[i];
        }
    }

    if (!pkcs7_unpad(out, blockSize)) {
        // 填充非法，返回空
        return {};
    }
    return out;
}

// ========== 封装成：字符串 <-> hex ==========

// 明文字符串 -> hex 密文字符串（ECB+PKCS#7）
string des_ecb_encrypt_string_to_hex(const string &plaintext, uint64_t key) {
    vector<uint8_t> plainBytes = string_to_bytes(plaintext);
    vector<uint8_t> cipherBytes = des_ecb_encrypt_bytes(plainBytes, key);
    return bytes_to_hex(cipherBytes);
}

// hex 密文字符串 -> 明文字符串（ECB+PKCS#7）
string des_ecb_decrypt_hex_to_string(const string &cipherHex, uint64_t key) {
    vector<uint8_t> cipherBytes = hex_to_bytes(cipherHex);
    vector<uint8_t> plainBytes = des_ecb_decrypt_bytes(cipherBytes, key);
    if (plainBytes.empty()) return "";
    return bytes_to_string(plainBytes);
}

// ========== 示例：直接丢字符串进去 ==========

int main() {
    int main() {
    // ============================
    // 只需要改下面三行
    // ============================

    string mode = "decrypt";  
    // 可选： "encrypt" 或 "decrypt"

    uint64_t key = 0x133457799BBCDFF1;  
    // 题目给的 DES 密钥（64 位）

    string inputStr = "85E813540F0AB405";  
    // encrypt 模式：填明文字符串
    // decrypt 模式：填 HEX 密文字符串

    // ============================
    // 以下无需修改
    // ============================

    if (mode == "encrypt") {
        string cipherHex = des_ecb_encrypt_string_to_hex(inputStr, key);
        cout << "[+] Plaintext : " << inputStr << endl;
        cout << "[+] CipherHex : " << cipherHex << endl;
    }
    else if (mode == "decrypt") {
        string plaintext = des_ecb_decrypt_hex_to_string(inputStr, key);
        cout << "[+] CipherHex : " << inputStr << endl;
        cout << "[+] Plaintext : " << plaintext << endl;
    }
    else {
        cout << "[-] mode 必须是 encrypt 或 decrypt" << endl;
    }

    return 0;
}
```

## 06 AES

和DES一样是分组加密，明文一组16字节128位，密钥可以为128，192或256位密钥的长度不同，推荐加密轮数也不同，如下表所示：

| AES     | 密钥长度（32位比特字) | 分组长度(32位比特字) | 加密轮数 |
| :------ | :-------------------- | :------------------- | :------- |
| AES-128 | 4                     | 4                    | 10       |
| AES-192 | 6                     | 4                    | 12       |
| AES-256 | 8                     | 4                    | 14       |

将16字节数据依序扔入4x4矩阵中，加密共十轮，每轮四个步骤，最后输出4x4矩阵，下面简单总结：

1. 字节代换：查S盒替换；
2. 行移位：对矩阵内的行简单移位换序；
3. 列混合：将行移位后的状态矩阵与固定的矩阵相乘；
4. 轮密钥加：128位轮密钥Ki（须原密钥通过算法生成）同状态矩阵中的数据逐位异或；

> AES 本体只是分组变换，实际加密还需要分组模式与填充规则。不同模式影响密文结构与可攻击面。
>
> - **常见模式：**
>   - **ECB:** 每块独立加密，无 **IV**。模式泄露结构特征，CTF常用来让你识别相同块重复。
>   - **CBC:** 每块明文先与前一块密文（第一块与 **IV**）异或，再加密；解密先解密再与前一块密文异或。
>   - **CTR:** 流模式，把计数器加密后与明文异或。
> - **填充（Padding）：**
>   - **PKCS#7:** 末块填充若干字节，每字节为填充长度。例如填充长度为 kk 则填入 kk 个值为 kk 的字节。逆向时容易通过结尾重复字节识别。
>   - **Zero/ANSI X.923/ISO 10126:** 变体填充，识别上要看末尾结构和长度字段处理。

**识别特征：**

- **S 盒常量：** 256 字节表（0x63、0x7C、0x77、…开头），逆 S 盒也可能出现。
- **Rcon：** 轮常数序列（0x01,0x02,0x04,0x08,…），常与密钥扩展相邻。

**解密代码：**

**python调库版：**

默认**CBC模式**，如果题目用 **ECB 模式**：把 `AES.MODE_CBC` 改成 `AES.MODE_ECB`，不需要 IV。

```py
#默认CBC模式，如果题目用 ECB 模式：把 `AES.MODE_CBC` 改成 `AES.MODE_ECB`，不需要 IV。

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# 已知的密钥和 IV（举例，长度必须符合 AES 要求）
key = b"thisisakey123456"   # 16字节 -> AES-128
#key：必须是 16/24/32 字节，分别对应 AES-128/192/256。
iv  = b"thisisanIV123456"   # 16字节 IV

# 已知的密文（这里假设你已经拿到）
ciphertext = bytes.fromhex("d0a1f3e2...")  
# 用十六进制字符串转成字节

# 创建 AES CBC 解密器
cipher = AES.new(key, AES.MODE_CBC, iv)

# 解密并去掉填充
plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

print("解密结果:", plaintext.decode("utf-8", errors="ignore"))

```

**不用库的完整版（cpp）：**(AES-128,ECB)

```CPP
#include <iostream>
#include <vector>
#include <cstdint>
#include <cstring>

// AES 参数
#define Nb 4        // block size (words)
#define Nk 4        // key size (words) -> AES-128
#define Nr 10       // number of rounds

// AES S-box 和逆S-box
static const uint8_t sbox[256] = {
    // 省略，需完整256字节表
};

static const uint8_t inv_sbox[256] = {
    // 省略，需完整256字节表
};

// Rcon 常量
static const uint8_t Rcon[11] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36
};

// 密钥扩展
void KeyExpansion(const uint8_t* key, uint8_t roundKey[176]) {
    int i = 0;
    uint8_t temp[4];
    while (i < Nk) {
        roundKey[4*i+0] = key[4*i+0];
        roundKey[4*i+1] = key[4*i+1];
        roundKey[4*i+2] = key[4*i+2];
        roundKey[4*i+3] = key[4*i+3];
        i++;
    }
    i = Nk;
    while (i < Nb*(Nr+1)) {
        temp[0] = roundKey[4*(i-1)+0];
        temp[1] = roundKey[4*(i-1)+1];
        temp[2] = roundKey[4*(i-1)+2];
        temp[3] = roundKey[4*(i-1)+3];
        if (i % Nk == 0) {
            // RotWord
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            // SubWord
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
            // Rcon
            temp[0] ^= Rcon[i/Nk];
        }
        roundKey[4*i+0] = roundKey[4*(i-Nk)+0] ^ temp[0];
        roundKey[4*i+1] = roundKey[4*(i-Nk)+1] ^ temp[1];
        roundKey[4*i+2] = roundKey[4*(i-Nk)+2] ^ temp[2];
        roundKey[4*i+3] = roundKey[4*(i-Nk)+3] ^ temp[3];
        i++;
    }
}

// AddRoundKey
void AddRoundKey(uint8_t state[4][4], const uint8_t* roundKey, int round) {
    for (int c = 0; c < 4; c++) {
        for (int r = 0; r < 4; r++) {
            state[r][c] ^= roundKey[round*Nb*4 + c*Nb + r];
        }
    }
}

// InvShiftRows
void InvShiftRows(uint8_t state[4][4]) {
    uint8_t temp;
    // row1
    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;
    // row2
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;
    // row3
    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

// GF(2^8) 乘法
uint8_t xtime(uint8_t x) { return (x<<1) ^ ((x>>7) * 0x1b); }
uint8_t mul(uint8_t x, uint8_t y) {
    uint8_t r = 0;
    while (y) {
        if (y & 1) r ^= x;
        x = xtime(x);
        y >>= 1;
    }
    return r;
}

// InvMixColumns
void InvMixColumns(uint8_t state[4][4]) {
    for (int c = 0; c < 4; c++) {
        uint8_t a0 = state[0][c], a1 = state[1][c], a2 = state[2][c], a3 = state[3][c];
        state[0][c] = mul(a0,0x0e) ^ mul(a1,0x0b) ^ mul(a2,0x0d) ^ mul(a3,0x09);
        state[1][c] = mul(a0,0x09) ^ mul(a1,0x0e) ^ mul(a2,0x0b) ^ mul(a3,0x0d);
        state[2][c] = mul(a0,0x0d) ^ mul(a1,0x09) ^ mul(a2,0x0e) ^ mul(a3,0x0b);
        state[3][c] = mul(a0,0x0b) ^ mul(a1,0x0d) ^ mul(a2,0x09) ^ mul(a3,0x0e);
    }
}

// InvSubBytes
void InvSubBytes(uint8_t state[4][4]) {
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            state[r][c] = inv_sbox[state[r][c]];
}

// AES 解密单个块 (16字节)
void AES_decrypt_block(uint8_t in[16], const uint8_t roundKey[176]) {
    uint8_t state[4][4];
    for (int i = 0; i < 16; i++) state[i%4][i/4] = in[i];

    AddRoundKey(state, roundKey, Nr);
    for (int round = Nr-1; round >= 1; round--) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, roundKey, round);
        InvMixColumns(state);
    }
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, roundKey, 0);

    for (int i = 0; i < 16; i++) in[i] = state[i%4][i/4];
}

int main() {
    // 示例：AES-128 ECB 解密
    uint8_t key[16] = { 't','h','i','s','i','s','a','k','e','y','1','2','3','4','5','6' };
    uint8_t roundKey[176];
    KeyExpansion(key, roundKey);

    uint8_t ciphertext[16] = { /* 16字节密文 */ };
    AES_decrypt_block(ciphertext, roundKey);

    std::cout << "解密结果: ";
    for (int i = 0; i < 16; i++) std::cout << (char)ciphertext[i];
    std::cout << std::endl;
}

```


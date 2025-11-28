---
title: re加密算法总结
date: 2025-11-27
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

// XXTEA 解密
void xxtea_decrypt(std::vector<uint32_t>& v, const std::array<uint32_t,4>& k) {
    const uint32_t DELTA = 0x9E3779B9;
    size_t n = v.size();
    if (n < 2) return;

    uint32_t q = 6 + 52 / n;
    uint32_t sum = q * DELTA;
    uint32_t y = v[0], z;

    while (sum != 0) {
        uint32_t e = (sum >> 2) & 3;
        for (size_t p = n-1; p > 0; --p) {
            z = v[p-1];
            uint32_t kpe = k[(p ^ e) & 3];
            v[p] -= (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (kpe ^ z));
            y = v[p];
        }
        z = v[n-1];
        uint32_t kpe0 = k[(0 ^ e) & 3];
        v[0] -= (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (kpe0 ^ z));
        y = v[0];
        sum -= DELTA;
    }
}

int main() {
    // 示例数据：两个 32 位整数
    std::vector<uint32_t> data = {0x12345678, 0x9abcdef0};
    std::array<uint32_t,4> key = {1,2,3,4};

    xxtea_encrypt(data, key);
    std::cout << "Encrypted: " << std::hex << data[0] << " " << data[1] << "\n";

    xxtea_decrypt(data, key);
    std::cout << "Decrypted: " << std::hex << data[0] << " " << data[1] << "\n";
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

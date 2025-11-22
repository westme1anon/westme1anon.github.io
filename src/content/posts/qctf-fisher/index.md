---
title: qctf-fisher
tags: [wp, re, hook, qctf]
category: CTF
description: inline hook分析
published: 2025-11-06
---

# fisher

## 0x01 解密

ida打开文件，main函数：

![image-20251108183320408](image-20251108183320408.png)

将输入加密为str1与密文比较，加密逻辑为换表base64；

![image-20251108183552278](image-20251108183552278.png)

fake flag;

尝试动调也错，感觉strcmp不能正常执行；

动调进入strcmp，发现系统指令被修改为一个jmp，进入后出现真正的加密函数

![image-20251108195116827](image-20251108195116827.png)

输入每八位执行一个tea加密（sub_7ff)，v5是密文，v9是key（后八位是0）；

```
#include<iostream>
#include<string>
#include<algorithm>
#include<vector>
#include<print>
#include<stdint.h>
using namespace std;

unsigned char v5[64]={};
unsigned char v9[16]={};

void tea_dec(uint32_t* v, uint32_t* k) {
    uint32_t v0 = v[0], v1 = v[1];  // v0、v1分别是密文的左、右半部分
    uint32_t delta = -1835914967;     //作为sum每次累加的变化值，题目中往往会修改此值
    uint32_t sum = 32 * delta;      //此处需要分析32轮加密结束后sum的值与delta的变化, 以此处加密为例子，32轮每次sum+=delta，因此最后sum=32*delta
    for (int i = 0; i < 32; i++) {  // tea加密进行32轮
        //根据加密时的顺序颠倒下面3行的顺序，将加法改为减法（异或部分都是整体，不用管），就是逆向解密过程
        v1 -= ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
        v0 -= ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        sum -= delta;
    }
    // 因此解密后的内容要还给v数组
    v[0] = v0;
    v[1] = v1;
}
 int main()
 {
  v5[0] = 8;
  v5[1] = -18;
  v5[2] = 89;
  v5[3] = 77;
  v5[4] = 13;
  v5[5] = -32;
  v5[6] = -64;
  v5[7] = -119;
  v5[8] = -95;
  v5[9] = -104;
  v5[10] = -78;
  v5[11] = -69;
  v5[12] = -49;
  v5[13] = 112;
  v5[14] = 127;
  v5[15] = -27;
  v5[16] = -24;
  v5[17] = 47;
  v5[18] = -102;
  v5[19] = -118;
  v5[20] = 32;
  v5[21] = -53;
  v5[22] = 116;
  v5[23] = 18;
  v5[24] = -14;
  v5[25] = 48;
  v5[26] = 120;
  v5[27] = 31;
  v5[28] = 14;
  v5[29] = -21;
  v5[30] = 31;
  v5[31] = -120;
  v5[32] = -56;
  v5[33] = -68;
  v5[34] = 78;
  v5[35] = -8;
  v5[36] = 82;
  v5[37] = 19;
  v5[38] = 83;
  v5[39] = -117;
  v5[40] = -99;
  v5[41] = -65;
  v5[42] = 102;
  v5[43] = 11;
  v5[44] = 106;
  v5[45] = -84;
  v5[46] = 33;
  v5[47] = 79;
  v5[48] = -23;
  v5[49] = 31;
  v5[50] = 70;
  v5[51] = 70;
  v5[52] = -98;
  v5[53] = -53;
  v5[54] = -6;
  v5[55] = 99;
  v5[56] = -93;
  v5[57] = -123;
  v5[58] = 20;
  v5[59] = -55;
  v5[60] = 46;
  v5[61] = -9;
  v5[62] = 16;
  v5[63] = -59;
  v9[0] = 17;
  v9[1] = 34;
  v9[2] = 51;
  v9[3] = 68;
  v9[4] = 85;
  v9[5] = 102;
  v9[6] = 119;
  v9[7] = -120;
  for (int i = 0;i <= 7;i++)
  {
    tea_dec((uint32_t*)(v5+8*i), (uint32_t*)v9);
  }
  for (char a : v5)
  cout<<a;
 }
```

输出：zCN7zTJg0xnEzxjJywV50xn53CvO4vZPyxrF2SzFzwr53SBQ0fZV1TvOxSj70xrZ；

因为调用的是str1，所以还要base64回去，

flag{Fisherman_is_very_satisfied_with_your_bait}



## 0x02 hook原理分析

查看真实加密函数调用，找到这样的函数

![image-20251108204603109](image-20251108204603109.png)

查询后是一个inline_hook

将strcmp的函数地址存到strcmp_0中，然后执行下面函数（sub_1150或a2即为加密函数）

![image-20251108205129255](image-20251108205129255.png)

9727转hex为0x25ff，转小端ff 25为jmp的字节码，小端存进qword src[0]的低四位，

两行结束src[0]为00 00 00 00 ff 25 00 00 ，

<!--         highword|lowword(小端序)      -->

第三行从第七位00开始换为a2的地址，构建出src为jmp a2的指令，

再将新的src地址赋给*lpadress,即strcmp_0的地址,即原来库函数strcmp的地址，

<!--改指针不用管执行顺序，直接相当与将指向库函数strcmp的指针strcmp_0指向了jmp a2；-->

这样就完成了对strcmp的hook动态替换。

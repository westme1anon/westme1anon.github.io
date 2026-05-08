---
title: qctf三道很有意思的题目汇总
tags: [wp, re, flower, hook, try catch]
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



# flowers

ida打开找标红，很明显的强制错误跳转，直接nop；

![image-20251127114504502](./image-20251127114504502-1778158560932-2.png)

call里面对栈顶rsp强制+9再return，等价直接到147F+9=1488的地址，所以call到1487直接nop；

![image-20251127114621155](./image-20251127114621155-1778158560932-1.png)

经典xor自己再test，jnz一定不执行，jz一定执行，nop掉jnz再改地址；

![image-20251127115450506](./image-20251127115450506-1778158560933-4.png)

![image-20251127115525872](./image-20251127115525872-1778158560933-3.png)

和第二个花一样；

![image-20251127115551926](./image-20251127115551926-1778158560933-5.png)

不红了，成功！

![image-20251127115653979](./image-20251127115653979-1778158560933-6.png)

f5出来明显tea；

![image-20251127115743639](./image-20251127115743639-1778158560933-7.png)

何意味？

![image-20251127120238796](./image-20251127120238796-1778158560933-8.png)

找main函数引用发现前面还红了一块，继续改吧

![image-20251127124124822](./image-20251127124124822-1778158560933-9.png)

也就那几种一样的花，不写了；

改完f5，

![image-20251127124731529](./image-20251127124731529-1778158560933-10.png)

![image-20251127125250657](./image-20251127125250657-1778158560933-12.png)

感觉就一个魔改tea，其他都是检验之类；

![image-20251127141934075](./image-20251127141934075-1778158560933-11.png)

*j<v3/4看上去加密了12次，但因为传的是8乘j，后面越界了，实际上只加密了六次。*

```cpp
#include<iostream>
#include<string>
#include<algorithm>
#include<vector>
#include<cstdint>
using namespace std;

uint32_t cipher[] = {0x47A215A5,0xDB8F1C31,0x916ABF13,0xDE25122F,0x66F52649,0x4E9B0E55,0x3D5219DF,0xCFB66388,0x3D5219DF,0xCFB66388,0x3D5219DF,0xCFB66388};
uint32_t key[] = {0x1234567,0x89ABCDEF,0xFEDCBA98,0x76543210};

void tea_dec(uint32_t* v, uint32_t* k) {
    uint32_t v0 = v[0], v1 = v[1];  // v0、v1分别是密文的左、右半部分
    uint32_t delta = 0x114514 ;     //作为sum每次累加的变化值，题目中往往会修改此值
    uint32_t sum = 32 * delta;      //此处需要分析32轮加密结束后sum的值与delta的变化, 以此处加密为例子，32轮每次sum+=delta，因此最后sum=32*delta
    for (int i = 0; i < 32; i++) {  // tea加密进行32轮
        //根据加密时的顺序颠倒下面3行的顺序，将加法改为减法（异或部分都是整体，不用管），就是逆向解密过程
        v1 -= ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
        sum -= delta;
        v0 -= ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
    }
    // 因此解密后的内容要还给v数组
    v[0] = v0;
    v[1] = v1;
}

int main()
{
    for (int i = 0; i < 6; i++)
        tea_dec (cipher+2*i, key) ;
    for (int i = 0 ;i <= 47; i++)
        cout << *((char*)cipher+i) ;
}
```

**flag{aCupOf_FlowerTea}**##



# hachimi

## 0x01 去trycatch反调试

ida打开发现很明显代码不完整，看到trylevel这个函数，搜索知是用于修改trycatch异常处理等级的函数，程序很可能是通过trycatch进行混淆；

![image-20251109155425794](./image-20251109155425794-1778158595535-25.png)

看汇编，真正程序应该在except块里，

![image-20251109161232841](./image-20251109161232841-1778158595535-26.png)

正常逻辑如下进入4e1357

![image-20251109161610905](./image-20251109161610905-1778158595535-27.png)

其中注意到dir ecx，ecx是0，这里抛出除零异常进入expect块；

![image-20251109161640762](./image-20251109161640762-1778158595535-28.png)

流程如下：ida默认了jmp从而忽略了expect的反编译；

// ida不能识别异常，函数只有通过jge再到jmp一条路可走，认为上面_except这一块永远不会执行；

![image-20251109171126516](./image-20251109171126516-1778158595535-31.png)

既然jmp_145e不会执行，那就把jmp_145e nop掉,后面还有个except过滤器也nop了；

代码就正常了；

// 这样让expect一定会顺序执行，因为他本来就一定会执行，所以正好是对的

![image-20251109173030682](./image-20251109173030682-1778158595535-29.png)

## 0x02 去花

![image-20251109173144206](./image-20251109173144206-1778158595535-30.png)

加密代码不完整，继续看汇编；

![image-20251109173230475](./image-20251109173230475-1778158595536-32.png)

下面的call_+5和jz很明显是花，直接force jump,得到完整加密；

![image-20251109182400912](./image-20251109182400912-1778158595536-33.png)

先tea后异或，解密如下：

```cpp
#include<iostream>
#include<string>
#include<algorithm>
#include<vector>
#include<stdint.h>
using namespace std;

uint32_t v8[4]={};
uint8_t v9[32]={0x4D,0x7A,0x3E,0x7A,0x84,0xFF,0x51,0xB1,0x31,0x97,0xFB,0xDC,0x2B,0xA4,0xCD,0xFB,0x85,0xCD,0xA,0x2B,0xBD,0x91,0xCF,0x69,0xBA,0x2B,0x70,0xD5,0x43,0xB8,0x3E,0x1f};

 unsigned long byteswap_manual(unsigned long value)  //转大小端的函数
 {
 return ((value>>24) & 0xFF) |
((value >> 8) & 0xFF00) | 
((value << 8) & 0xFF0000) |
((value << 24) & 0xff0000);
 }


void tea_dec(uint32_t* a1, uint32_t* a2) {
  unsigned __int32 result; // eax
  unsigned int i; // [esp+8h] [ebp-14h]
  int j; // [esp+Ch] [ebp-10h]
  unsigned int v5 = 0; // [esp+10h] [ebp-Ch]
  unsigned int v6 = 0; // [esp+14h] [ebp-8h]
    for ( j = 0; j < 8; ++j )
  {
    *((uint8_t *)a1 + j) ^= *(uint8_t *)(a2 + 15 - j);
  }
  *a1 = byteswap_manual(*a1);
  *(a1+1) = byteswap_manual(*(a1+1));
    uint32_t v0 = a1[0], v1 = a2[1];  // v0、v1分别是密文的左、右半部分
    uint32_t delta = 1640531527;     //作为sum每次累加的变化值，题目中往往会修改此值
    uint32_t v7 = 32 * (-delta);      //此处需要分析32轮加密结束后sum的值与delta的变化, 以此处加密为例子，32轮每次sum+=delta，因此最后sum=32*delta
    for (int i = 0; i < 32; i++) {  // tea加密进行32轮
        //根据加密时的顺序颠倒下面3行的顺序，将加法改为减法（异或部分都是整体，不用管），就是逆向解密过程
    v5 -= (*(uint32_t *)(a2 + 4 * ((v7 >> 11) & 3)) + v7) ^ (v6 + ((v6 >> 5) ^ (16 * v6)));
    v7 += 1640531527;
    v6 -= (*(uint32_t *)(a2 + 4 * (v7 & 3)) + v7) ^ (v5 + ((v5 >> 5) ^ (16 * v5)));
    }
    // 因此解密后的内容要还给v数组
    *(uint32_t*)(v9+j) = v0;
    *(uint32_t*)(v9+j) = v1;
  return ;
}

int main()
{
  v8[0] = 1495531287;
  v8[1] = -1758678609;
  v8[2] = -880611118;
  v8[3] = -38157364;
  for(int j = 0;j < 8;j+=2)
    tea_dec((uint32_t*)(v9+j),v8);
  for(char a:v9)
    cout<<a;
}
```

 flag{ha_ha_hachimi_na_bei_lu_do};

---
title: 基本Hook
date: 2026-05-28
tags: [re, wiki]
category: WIKI
published: 2026-05-28
description: 正在更新...
---

# Inline Hook

### 核心思想

Inline Hook 是在**目标函数体内部**直接修改机器码，插入跳转指令，使执行流劫持到自定义函数，执行完后再跳回原函数继续执行。

也是Frida在Native层的hook方式（Interceptor）。

### 基本原理

以 x86-64 为例，最常见的做法是在函数开头写入一条 `jmp` 指令：

```
原始函数头:
55          push rbp
48 89 EC    mov  rbp, rsp
...

Hook 后:
E9 XX XX XX XX   jmp <hook_func>   ← 覆盖了原来的字节
...
```

`jmp rel32` 只有 5 字节，是最常见的 hook 跳板。绝对跳转（跳到任意地址）需要更多字节：

| 方式                     | 字节数 | 备注               |
| ------------------------ | ------ | ------------------ |
| `jmp rel32`              | 5      | 仅限 ±2GB 范围     |
| `mov rax, addr; jmp rax` | 12     | 绝对跳转，x64 常用 |
| `push addr; ret`         | 14     | 等效绝对跳转       |

------

### 完整执行流

```
目标函数                    Hook 函数                   Trampoline（跳板）
┌─────────────┐            ┌─────────────────┐         ┌────────────────────┐
│ jmp hook ───┼──────────► │ 执行自定义逻辑   │         │ 被覆盖的原始字节   │
│ ...         │            │                 │         │ jmp 原函数+5      │
│             │            │ call trampoline ├────────►│                    │
│             │◄───────────┼─────────────────┘         └────────────────────┘
│ 继续执行... │
```

关键步骤：

1. **备份**被覆盖的原始字节（通常 5~14 字节）
2. **写入跳转**到 hook 函数，此函数返回 trampolline
3. 构造 **trampoline**：原始字节 + 跳回原函数 hook 点之后
4. hook 函数中调用 trampoline 实现"透明"调用

### 代码示例

```c
#include <windows.h>
#include <stdint.h>

uint8_t original_bytes[14];  // 备份原始字节
void *trampoline;

// hook 函数，替代 MessageBoxA
int WINAPI hk_MessageBoxA(HWND hWnd, LPCSTR lpText,
                           LPCSTR lpCaption, UINT uType) {
    // 修改参数后调用 trampoline（原始函数）
    typedef int (WINAPI *pMsgBox)(HWND, LPCSTR, LPCSTR, UINT);
    return ((pMsgBox)trampoline)(hWnd, "Hooked!", lpCaption, uType);
}

void install_hook(void *target, void *hook_fn) {
    DWORD old_prot;
    
    // 1. 备份原始字节（12 字节绝对跳转）
    memcpy(original_bytes, target, 12);
    
    // 2. 构造 trampoline（在可执行内存中）
    trampoline = VirtualAlloc(NULL, 32,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    uint8_t *t = (uint8_t *)trampoline;
    memcpy(t, original_bytes, 12);   // 原始字节
    // jmp 回 target+12
    t[12] = 0x48; t[13] = 0xB8;     // mov rax, imm64
    *(uint64_t *)(t + 14) = (uint64_t)target + 12;
    t[22] = 0xFF; t[23] = 0xE0;     // jmp rax
    
    // 3. 修改页面权限，写入跳转
    VirtualProtect(target, 12, PAGE_EXECUTE_READWRITE, &old_prot);
    uint8_t *p = (uint8_t *)target;
    p[0] = 0x48; p[1] = 0xB8;       // mov rax, imm64
    *(uint64_t *)(p + 2) = (uint64_t)hook_fn;
    p[10] = 0xFF; p[11] = 0xE0;     // jmp rax
    VirtualProtect(target, 12, old_prot, &old_prot);
}
```

> #### 全局变量
>
> ```c
> uint8_t original_bytes[14];  // 备份被覆盖的原始字节
> void *trampoline;            // trampoline 的内存地址
> ```
>
> 这两个全局变量是 hook 机制的核心状态，贯穿整个生命周期。
>
> #### Hook 函数本体
>
> ```c
> int WINAPI hk_MessageBoxA(HWND hWnd, LPCSTR lpText,
>                         LPCSTR lpCaption, UINT uType) {
>  typedef int (WINAPI *pMsgBox)(HWND, LPCSTR, LPCSTR, UINT);
>  return ((pMsgBox)trampoline)(hWnd, "Hooked!", lpCaption, uType);
> }
> ```
>
> 签名必须和原函数完全一致。
>
> **`typedef` 定义函数指针类型**：
>
> ```c
> typedef int (WINAPI *pMsgBox)(HWND, LPCSTR, LPCSTR, UINT);
> ```
>
> #### 调用 trampoline:
>
> ```c
> return ((pMsgBox)trampoline)(hWnd, "Hooked!", lpCaption, uType);
> //      ──────────────────    ────   ────────   ─────────   ────
> //      把 void* 转成函数指针  原参数  替换了这个  原参数      原参数
> ```
>
> - `trampoline` 是 `void*`，不能直接调用
> - 强转成 `(pMsgBox)` 后就可以像函数一样加括号调用
> - 把 `lpText` 替换成 `"Hooked!"`，其他参数原样透传
> - 通过 `trampoline` 调用**原始的** `MessageBoxA`，形成完整链路
>
> ------
>
> #### install_hook 函数:
>
> ```c
> void install_hook(void *target, void *hook_fn)
> ```
>
> - `target`：要 hook 的原始函数地址（如 `MessageBoxA` 的地址）
> - `hook_fn`：我们的 hook 函数地址（`hk_MessageBoxA`）
>
> ##### 第一步：备份原始字节
>
> ```c
> memcpy(original_bytes, target, 12);
> ```
>
> 后续会用 12 字节的跳转指令覆盖 `target` 开头，所以先把这 12 字节保存下来。
>
> **Q:**为什么是 12 字节？因为后面写入的绝对跳转指令正好 12 字节：
>
> ```
> 48 B8 xx xx xx xx xx xx xx xx   → mov rax, imm64  (10字节)
> FF E0                           → jmp rax          (2字节)
>                                                   = 12字节
> ```
>
> ##### 第二步：构造 Trampoline
>
> ```c
> trampoline = VirtualAlloc(NULL, 32,
>     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
> ```
>
> `VirtualAlloc` 参数含义：
>
> ```
> NULL                    → 让系统选择地址
> 32                      → 分配 32 字节（够用）
> MEM_COMMIT|MEM_RESERVE  → 直接提交物理内存
> PAGE_EXECUTE_READWRITE  → 可读可写可执行
> ```
>
> ```c
> uint8_t *t = (uint8_t *)trampoline;
> memcpy(t, original_bytes, 12);   // 把原始 12 字节复制进来
> ```
>
> Trampoline 的前 12 字节 = 原函数被覆盖掉的原始指令。
>
> 此时 trampoline 内存布局：
>
> ```
> t[0..11]  = 原始指令（从 target 备份来的）
> t[12..23] = 待写入：jmp 回 target+12
> ```
>
> ```c
> t[12] = 0x48; t[13] = 0xB8;              // mov rax, imm64 的前缀
> *(uint64_t *)(t + 14) = (uint64_t)target + 12;  // 写入目标地址
> t[22] = 0xFF; t[23] = 0xE0;              // jmp rax
> ```
>
> 逐字节解释：
>
> ```
> 偏移   字节      含义
>  0    48 B8     REX.W 前缀 + MOV RAX 操作码
>  2    xx*8      立即数：target+12 的 64 位地址（小端序）
> 10    FF E0     JMP RAX
> ```
>
> `target + 12` 是原函数中**跳过被覆盖的 12 字节之后**的位置，也就是原始逻辑继续执行的地方。
>
> 完整的 trampoline 内存：
>
> ```
> [原始指令 0..11] [mov rax, target+12] [jmp rax]
>       ↑                                    ↓
>   执行原始逻辑                        跳回原函数继续
> ```
>
> ##### 第三步：在原函数头写入跳转
>
> ```c
> VirtualProtect(target, 12, PAGE_EXECUTE_READWRITE, &old_prot);
> ```
>
> 原函数代码段默认是 `PAGE_EXECUTE_READ`（可执行但**不可写**），必须先改权限才能写入跳转指令。`old_prot` 保存旧权限，之后还原用。
>
> ```c
> uint8_t *p = (uint8_t *)target;
> p[0] = 0x48; p[1] = 0xB8;               // mov rax, imm64
> *(uint64_t *)(p + 2) = (uint64_t)hook_fn; // 写入 hook 函数地址
> p[10] = 0xFF; p[11] = 0xE0;             // jmp rax
> ```
>
> 和 trampoline 里的跳转结构完全一样，只是目标地址换成了 `hook_fn`：
>
> ```
> 原函数头（修改前）:          原函数头（修改后）:
> 55          push rbp         48 B8           mov rax, hook_fn地址
> 48 89 EC    mov rbp,rsp  →   xx xx xx xx
> ...                          xx xx xx xx
>                              FF E0           jmp rax
> ```
>
> ------
>
> ```c
> VirtualProtect(target, 12, old_prot, &old_prot);
> ```
>
> 还原内存权限，减少被安全软件检测到可疑内存页的概率。
>
> ------
>
> #### 完整执行流程
>
> ```
> 程序调用 MessageBoxA
>         │
>         ▼
> 原函数头：mov rax, hk_MessageBoxA; jmp rax
>         │
>         ▼
> hk_MessageBoxA 执行
>   把 lpText 改成 "Hooked!"
>   调用 trampoline
>         │
>         ▼
> trampoline：
>   [原始 push rbp; mov rbp,rsp ...]   ← 执行被覆盖的原始指令
>   mov rax, target+12
>   jmp rax
>         │
>         ▼
> 回到原函数 +12 偏移处继续执行
>         │
>         ▼
> MessageBoxA 正常弹出，但文本是 "Hooked!"
> ```
>
> ------
>
> #### 内存布局总览
>
> ```
> 原函数 target:                    trampoline（新分配）:
> ┌──────────────────┐              ┌──────────────────────────┐
> │ mov rax, hook_fn │──┐     ┌───►│ push rbp                 │
> │ jmp rax          │  │     │    │ mov rbp, rsp             │（原始12字节）
> │ [target+12...]   │◄─┼─────┼──┐ │ ...                      │
> │ 原函数剩余逻辑    │  │     │  │ ├──────────────────────────┤
> └──────────────────┘  │     │  │ │ mov rax, target+12       │
>                        │     │  └─│ jmp rax                  │
> hook 函数:             │     │    └──────────────────────────┘
> ┌──────────────────┐  │     │
> │ hk_MessageBoxA   │◄─┘     │
> │ 修改参数...       │        │
> │ call trampoline  │────────┘
> └──────────────────┘
> ```

本质就是再原函数前插入一个函数去修改函数行为（传参等），最后还是要重新调用原函数。


# IAT/GOT HOOK

#### 原理

PE 文件有**导入地址表（IAT）**，ELF 有**全局偏移表（GOT）**，动态链接时加载器会把外部函数的真实地址填进去。

> 程序不可能把所有功能自己实现，会调用 `printf`、`CreateFile`、`malloc` 等**别的库**里的函数。那么：
>
> - **我提供函数给别人用** → 导出表（Export Table）
> - **我用别人提供的函数** → 导入表（Import Table）
>
> 如：
>
> ```
> kernel32.dll 的导出表（简化）:
> ┌──────────────────┬──────────────┐
> │ 函数名           │ RVA（相对地址）│
> ├──────────────────┼──────────────┤
> │ CreateFileA      │ 0x00012345   │
> │ CreateFileW      │ 0x00012400   │
> │ ReadFile         │ 0x00015678   │
> │ WriteFile        │ 0x00016000   │
> │ ...              │ ...          │
> └──────────────────┴──────────────┘
> ```
>
> ```
> notepad.exe 的导入表（简化）:
> ┌─────────────┬────────────────────────────────────┐
> │ 来自哪个DLL  │ 需要的函数                          │
> ├─────────────┼────────────────────────────────────┤
> │ kernel32.dll│ CreateFileW, ReadFile, WriteFile... │
> │ user32.dll  │ MessageBoxW, DrawText, ...          │
> │ ntdll.dll   │ RtlAllocateHeap, NtQueryInfo...     │
> └─────────────┴────────────────────────────────────┘
> ```
>
> 在编译/运行时，将函数名加载为外部函数真实地址

Hook 的做法就是**直接替换表中的地址**，指向自己的函数。

```
正常调用流程:
call [IAT["MessageBoxA"]] ──► 0x7FFF...（真实地址）

IAT Hook 后:
call [IAT["MessageBoxA"]] ──► 0xDEAD...（hook 函数）
```

#### 代码示例（Windows IAT Hook）

```c
#include <windows.h>
#include <stdio.h>

void iat_hook(HMODULE hMod, const char *funcName, void *hookFn)
{
    // 解析 PE 头
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)hMod + dos->e_lfanew);

    // 定位导入表
    PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)hMod + nt->OptionalHeader                                              .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
.VirtualAddress);
    // 遍历每个DLL
    for (; imp->Name; imp++)
    {
        // 同时拿到 INT 和 IAT，用 orig（INT）来读函数名，用 thunk（IAT）来写地址
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE *)hMod + imp->FirstThunk);
        PIMAGE_THUNK_DATA orig = (PIMAGE_THUNK_DATA)((BYTE *)hMod + imp->OriginalFirstThunk);

        // 遍历函数，匹配名字
        for (; orig->u1.AddressOfData; orig++, thunk++)
        {
            PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)((BYTE *)hMod + orig->u1.AddressOfData);

            if (!strcmp((char *)ibn->Name, funcName))
            {
                // 修改内存权限并替换地址
                DWORD old;
                VirtualProtect(&thunk->u1.Function, 8,
                               PAGE_EXECUTE_READWRITE, &old);
                thunk->u1.Function = (ULONG_PTR)hookFn; // 替换
                VirtualProtect(&thunk->u1.Function, 8, old, &old);
            }
        }
    }
}

```

> #### 函数签名
>
> ```c
> void iat_hook(HMODULE hMod, const char *funcName, void *hookFn)
> ```
>
> - `hMod`：要 hook 的**目标模块**基址（比如 `GetModuleHandle("notepad.exe")`）
> - `funcName`：要 hook 的函数名，如 `"MessageBoxA"`
> - `hookFn`：替换成的函数指针
>
> #### 第一步：找到 NT 头
>
> ```c
> PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
> PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
> ```
>
> PE 文件内存布局是固定的：
>
> ```
> 模块基址 hMod
> │
> ├── IMAGE_DOS_HEADER         ← dos 指向这里
> │     ├── e_magic = "MZ"
> │     └── e_lfanew ──────────────────┐  偏移量，指向 NT 头
> │                                    │
> ├── DOS Stub（"This program cannot..."）
> │                                    │
> └── IMAGE_NT_HEADERS  ◄──────────────┘  nt 指向这里
>       ├── Signature = "PE\0\0"
>       ├── FileHeader
>       └── OptionalHeader
>             └── DataDirectory[16]   ← 关键目录数组
> ```
>
> `dos->e_lfanew` 就是 MZ 头里存的一个偏移值，告诉你 NT 头在哪。
>  `(BYTE*)hMod` 是为了让指针加法以**字节为单位**，避免类型步长问题。
>
> ------
>
> #### 第二步：找到导入表
>
> ```c
> PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)(
>     (BYTE*)hMod + nt->OptionalHeader
>         .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
> ```
>
> `DataDirectory` 是一个 16 格的目录数组，每格描述一种数据结构的位置：
>
> ```
> DataDirectory[0]  = 导出表
> DataDirectory[1]  = 导入表   ← IMAGE_DIRECTORY_ENTRY_IMPORT = 1
> DataDirectory[2]  = 资源表
> DataDirectory[4]  = 重定位表
> ...
> ```
>
> 每个 `DataDirectory` 条目是：
>
> ```c
> struct {
>     DWORD VirtualAddress;  // RVA（相对虚拟地址）
>     DWORD Size;
> };
> ```
>
> 所以 `hMod + VirtualAddress` = 导入表在内存中的**真实地址**。
>
> 导入表是一个 `IMAGE_IMPORT_DESCRIPTOR` **数组**，每个元素对应一个被导入的 DLL：
>
> ```
> imp[0] → kernel32.dll 的导入描述符
> imp[1] → user32.dll 的导入描述符
> imp[2] → ntdll.dll 的导入描述符
> imp[3] → { 全0 }   ← 数组结束标志
> ```
>
> ------
>
> #### 第三步：遍历每个 DLL
>
> ```c
> for (; imp->Name; imp++) {
> ```
>
> `imp->Name` 是 DLL 名称字符串的 RVA，为 0 表示数组结束。
>  每次 `imp++` 就跳到下一个 DLL 的描述符。
>
> 每个 `IMAGE_IMPORT_DESCRIPTOR` 结构是：
>
> ```c
> struct IMAGE_IMPORT_DESCRIPTOR {
>     DWORD OriginalFirstThunk;  // → INT（导入名称表），只读，含函数名
>     DWORD TimeDateStamp;
>     DWORD ForwarderChain;
>     DWORD Name;                // → DLL 名称字符串
>     DWORD FirstThunk;          // → IAT（导入地址表），运行时被填入真实地址
> };
> ```
>
> ------
>
> #### 第四步：同时拿到 INT 和 IAT
>
> ```c
> PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(
>     (BYTE*)hMod + imp->FirstThunk);          // IAT ← 要修改的
> 
> PIMAGE_THUNK_DATA orig  = (PIMAGE_THUNK_DATA)(
>     (BYTE*)hMod + imp->OriginalFirstThunk);  // INT ← 用来查名字
> ```
>
> 这是理解 IAT Hook 最关键的一步，两张表的关系：
>
> ```
> OriginalFirstThunk → INT（导入名称表）
>                       [0] → "MessageBoxA" 的 IMAGE_IMPORT_BY_NAME
>                       [1] → "DrawText" 的 IMAGE_IMPORT_BY_NAME
>                       [2] → NULL
> 
> FirstThunk        → IAT（导入地址表）
>                       [0] → 0x7FFF12345678  ← MessageBoxA 真实地址（加载后）
>                       [1] → 0x7FFF87654321  ← DrawText 真实地址
>                       [2] → NULL
> ```
>
> **两个数组一一对应，索引相同的条目指的是同一个函数。**
>
> 所以用 `orig`（INT）来**读函数名**，用 `thunk`（IAT）来**写地址**。
>  为什么不直接用 IAT 查名字？因为加载后 IAT 里已经是地址了，名字信息没了。
>
> ------
>
> #### 第五步：遍历函数，匹配名字
>
> ```c
> for (; orig->u1.AddressOfData; orig++, thunk++) {
>     PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)(
>         (BYTE*)hMod + orig->u1.AddressOfData);
>     
>     if (!strcmp((char*)ibn->Name, funcName)) {
> ```
>
> `PIMAGE_THUNK_DATA` 的 `u1` 是个联合体：
>
> ```c
> union {
>     ULONGLONG ForwarderString;
>     ULONGLONG Function;        // 加载后 IAT 用这个（存真实地址）
>     ULONGLONG Ordinal;         // 如果是序号导入
>     ULONGLONG AddressOfData;   // 加载前 INT 用这个（RVA → IMAGE_IMPORT_BY_NAME）
> };
> ```
>
> `IMAGE_IMPORT_BY_NAME` 结构：
>
> ```c
> struct IMAGE_IMPORT_BY_NAME {
>     WORD  Hint;        // 序号提示，加速查找用
>     CHAR  Name[1];     // 函数名字符串（变长）
> };
> ```
>
> 所以 `ibn->Name` 就是函数名，`strcmp` 匹配目标函数名。
>
> 整体数据关系图：
>
> ```
> orig[i].u1.AddressOfData (RVA)
>     │
>     ▼
> IMAGE_IMPORT_BY_NAME:
>     ├── Hint: 42
>     └── Name: "MessageBoxA\0"
> 
> thunk[i].u1.Function (运行时)
>     = 0x00007FFF_AABBCCDD  ← 真实地址，就改这里
> ```
>
> ------
>
> #### 第六步：修改内存权限并替换地址
>
> ```c
> DWORD old;
> VirtualProtect(&thunk->u1.Function, 8,
>     PAGE_EXECUTE_READWRITE, &old);
> 
> thunk->u1.Function = (ULONG_PTR)hookFn;  // 核心操作
> 
> VirtualProtect(&thunk->u1.Function, 8, old, &old);
> ```
>
> IAT 所在内存页默认是**只读**的（`.rdata` 段），直接写会访问冲突，所以：
>
> 1. `VirtualProtect` 先改成可读写可执行
> 2. 写入 hook 函数地址
> 3. `VirtualProtect` 还原原来的权限（`old` 参数复用，第二次调用时存入当前权限，无所谓）
>
> `(ULONG_PTR)hookFn` 是平台无关的指针整数转换：x86 是 32 位，x64 是 64 位。
>
> ------
>
> #### 完整数据流总结
>
> ```
> hMod（模块基址）
>  │
>  ├─[+e_lfanew]──► NT头
>  │                  └─ OptionalHeader.DataDirectory[1].VirtualAddress
>  │                                  │
>  ├─[+RVA]──────────────────────────►IMAGE_IMPORT_DESCRIPTOR[]
>  │                                    │            │
>  │                         OriginalFirstThunk   FirstThunk
>  │                                    │            │
>  │                              INT数组[]       IAT数组[]
>  │                                    │            │
>  │                              [函数名RVA]    [真实地址]  ← 改这里
>  │                                    │
>  └─[+RVA]──────────────────────────►IMAGE_IMPORT_BY_NAME
>                                        └─ Name: "MessageBoxA"
> ```
>
> 找到名字匹配的条目后，**把 IAT 对应位置改成 hookFn 的地址**，之后所有通过这个模块调用该函数的代码都会走到你的 hook 函数。

从PE模块层面找到导入函数表，遍历导入表函数名，匹配想要hook的函数名，根据函数名找对应偏移，替换指针。
---
title: 花指令
date: 2025-11-14
tags: [CTF, flower]
category: WIKI
published: 2025-11-14
description: 花指令总结，长期更新。
---

# 花指令总结

## *0x00 简介*

**花指令**~~是区~~是干扰反编译器正常分析的人为注入的垃圾指令，出题人通过插入一些垃圾（也可能会执行）汇编代码来让**反编译器错误反编译**，而**不会干扰程序正常执行**；

**修改花指令**相当于**修改（一般是简化）程序结构**但**不改变程序原有的执行逻辑**（本来就是正确的，只是ida弄错了），**易于（即改成ida能分析正确的样子）**我们的ida爹反汇编正确。

## 0x01   100%跳转到_地址+x

特征：

- jz/jnz/jmp等跳转指令后接（**函数地址+数字**）
- jz等条件跳转100%执行，或jz和jnz这种互补的条件跳转连着出现，即**强制执行条件跳转**

原理：

- **强制跳转的正常函数**的字节码前面部被添上了垃圾字节，这个垃圾字节**永远不会执行**
- 但反编译器不知道（地址+x）跳转是100%的，只会优先按正常执行顺序分析的字节*（原因可能是先执行等等）*
- 从而把垃圾指令当正常指令分析，把后面的东西全部带歪；

解决办法：

- nop掉强制跳转的正常函数前面的垃圾字节，再重定义（对下面的标红的字节拖一下按c强转成code，再返回函数头按u再按p）即可；

- 对于一堆**重复**的这样的花指令，可以**写py脚本批量处理**：

  ```py
  import idautils
  import idc
  
  def my_nop(addr, endaddr):  
      while addr < endaddr:
          patch_byte(addr, 0x90)
          addr += 1
  
  pattern = "E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF"   #重复花指令的字节串
  cur_addr = 0x456000		#开始地址
  end_addr = 0x467894		#结束地址
  
  while cur_addr<end_addr:
      cur_addr = idc.find_binary(cur_addr,SEARCH_DOWN,pattern)
      print("patch address: " + str(cur_addr)) # 打印提示信息
      if cur_addr == idc.BADADDR:
          break
      else:
          my_nop(cur_addr+5,cur_addr+6)  #想要nop的字节
          my_nop(cur_addr+8,cur_addr+14)  #想要nop的字节
      cur_addr = idc.next_head(cur_addr)
  # from https://www.52pojie.cn/thread-1512089-1-1.html
  ```

  or

  ```py
  startaddr = 0x????
  endaddr = 0x????
  
  for i in range(startaddr,endaddr)
  ​	if get_wide_byte(i) == 0xEB
  ​		if get_wide_byte(i+1) == 0xFF #嵌套判断输出（加精度）
  ​			patch_byte(i,0x90)
  ​			print("[+] addr {} is patched".format(hex(i)) #格式化输出提示
  ```

  > 使用IDA自带的脚本编辑器：
  >
  > IDA Pro提供了一个简单的脚本编辑器，可以用来编写和执行Python脚本：
  >
  > 1. **打开脚本编辑器**
  >
  >    在IDA的菜单栏中，选择“File”->“Script file”选项。这将打开一个文件选择对话框，允许你选择一个Python脚本文件。
  >
  > 2. **执行脚本**
  >
  >    选择你要执行的Python脚本文件，然后点击“Open”按钮。IDA会自动加载并执行该脚本。

举例：

1.  from 闻花识女人 *2025vn招新赛*

![image-20251115200727288](image-20251115200727288.png)

> `test`命令将两个操作数进行逻辑与运算，并根据运算结果设置相关的标志位。但是，Test命令的两个操作数**不会**被改变。运算结果在设置过相关标记位后会被丢弃。
>
> `TEST AX,BX` 与`AND AX,BX`命令有相同效果，只是Test指令不改变AX和BX的内容，而AND指令会把结果保存到AX中。

- rbx自身异或必然返回0，再test两个0必然也返回0，100%执行jz；

- nop掉 2cc4的e9 或 jnz那一行，再重定义即可；

2. from bili:UKFC战队

![image-20251115203040563](./image-20251115203040563.png)

- 4188f9的jz和jnz互补，必有一个执行；
- nop _18fd，其他同上；



## 0x02 废物call玩栈空间偏移return

特征：

- `call $+5`
- 接着*唐突*`pop xxx`+ 修改pop出的内容 +`push xxx`
- `retn`

原理：

> **CALL指令的执行步骤**：
>
> 1. **保存返回地址**：将当前指令的下一条指令地址（IP或CS:IP）压入栈中。
> 2. **跳转到目标地址**：根据CALL指令的目标地址，修改IP或CS:IP寄存器的值。

> call的作用是将程序的执行流程跳转到指定的子程序地址，并在子程序执行完毕后通过**RET指令**返回到调用点继续执行。CALL指令与JMP指令类似，**但增加了返回地址的保存功能**。

- call的字节码长度一般是5，`call $+5` (*我的理解* $相当与相对路径)等于什么也没执行，相当于顺序执行下去，**除了将call指令的下一个地址压到了栈**；

  > push/call等入栈的东西会优先存储在栈顶，push弹栈也是先弹栈顶

- 接着pop弹栈并将弹出的地址（即刚才call压栈的地址）存在一个寄存器里；

- 对这个寄存器进行修改；

- push把修改后的寄存器压入栈；

- return返回到修改后的地址；

- 这样就修改了call的return地址，但是ida默认call的返回地址不会被修改，这样就可以给**垃圾指令**留下空间，这些垃圾指令不会被执行但会被ida错误循序分析；

修改方法：

- 既然call是废物，那么把call和后面的一堆不执行的垃圾指令（到return的地址）全nop了就行，函数就会正确的顺序执行，也能正常分析

举例：

1.from dirty_flower

![image-20251115211807102](./image-20251115211807102.png)

- 分析如上，nop掉4012f2到401302即可；

## 0x03 重复计算



![image-20251115211504773](./image-20251115211504773.png)

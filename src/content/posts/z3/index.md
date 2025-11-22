---

title: z3求解器 
date: 2025-11-14
tags: [ctf, z3]
category: WIKI
description: z3的学习与使用
published: 2025-11-14
---

# 0x01 基本用法

## 求解器

在使用 `z3` 进行约束求解之前我们首先需要获得一个 *求解器* 类实例，**本质上其实就是一组约束的集合**：

```python
>>> s = z3.Solver()
```

## 变量

再创建用于解方程的变量

```python
import z3;
x = z3.Int(name = 'x')   #x是整形变量
y = z3.Real(name = 'y')   #y是实数
z = z3.BitVec(name= 'z', bv = 32)   #z是长度为32位的向量（向量长度需初始化）
p = z3.Bool(name = 'p')   #p是bool型
```

整型与实数类型变量之间可以互相进行转换：

```python
z3.ToReal(x)
z3.ToInt(y)
```

还能创建常量

```py
z3.IntVal(val = 114514) #int类型常量
```

## 添加约束

用add()方法为指定求解器添加约束，条件为初始化中变量组成的式子；

```py
s.add(x + 5 == 111)
s.add(y + 3 == x)
```

bool类型还可逻辑运算，暂且不表；

## 约束求解

使用check()方法寻找是否有解

```py
>>> s.check()
sat  #有解
# 返回unsat则无解
```

若有解则可以通过model()方法获取一组解；

```
>>> if s.check() == z3.sat:
   		print(s.model())
[y = 103, x = 106]
```

# 0x02 for CTF

## 初始化

不用写z3.前缀；

```py
from z3 import *
```

用循环创建变量

```py
v = [Int(f'v{i}')    for i in range(0, 16)]  #f'{}'用来格式化字符串，传入后面的i
# or
x = [0] * 16
for i in range(16):
    x[i] = Int('x[' + str(i) + ']')
```

## 求解

model()方法会返回一个列表，比如

```
[i11i1Iii1I1[14] = 49,
 i11i1Iii1I1[28] = 125,
 i11i1Iii1I1[27] = 51,
...
 i11i1Iii1I1[7] = 54]
```

接下来要做的是将解转化为字符，但由于该列表中的元素是z3中的特殊类型，需要先转换为python中的整数类型才能使用chr()函数转为对应字符;

但列表中解不是按未知参数或数组大小排序的，解决办法是循环访问列表中的值，将其作为索引去访问ans列表，即此处的【**ans[i]**】，然后使用as_long()函数将解的类型转为python中的int类型，最后使用chr()函数转为对应字符；

```py
if solver.check() == sat: #check()方法用来判断是否有解，sat(即satisify)表示满足有解
    ans = solver.model() #model()方法得到解
    for i in v:
        print(chr(ans[i].as_long()), end='')
#一般不会无解，如果无解八成是未知数变量的类型不符合，或约束方程添加错误
# or
if z3.Solver.check(s) == z3.sat: 
    ans = z3.Solver.model(s) 
    for i in i11i1Iii1I1:
        print(chr(ans[i].as_long()), end='')
```

# 0x03 板子

*原文链接：https://blog.csdn.net/liKeQing1027520/article/details/138047537*

*板子作者：CSDN-晴友读钟*

## 预处理字符串

```py
import re

def replace_func(match):
    shift = 2 #shift是指第一个未知数和0的差，例如：如果题目中第一个未知数是v2（如果是v3），那么shift就设置成2（就设置成3）
    index = int(match.group(1)) - shift
    return str(f'v[{index}]')  # 返回字符串'v[a后数字-1]'，用其替换匹配到的an

if __name__ == '__main__':
    s1 = ""  # 定义包含an的字符串
s1 = re.sub(r'v(2[0-9]|1[0-9]|[1-9])', replace_func, s1)
# sub函数参数, pattern、repl、string分别表示：正则表达式匹配规则、替换后结果（可以是函数也可以是常量）、要被查找替换的原始字符串
s1 = re.sub('!', '=', s1) #有些题目给的条件的方程是用'||'关系运算符连接的不等式方程，需要用这一行代码将'!'替换成'='变成等式方程
res = s1.split('| | ')
print(res)
```

**（ida）** 将整串条件复制过来放进s1中之后，把多余的换行和空格删除掉*（shift+tab删除缩进）*，形成一连串的由关系运算符连接的条件；

接着你根据条件中具体的关系运算符，到底是"&&"还是"||"来使用split()函数将每个方程分隔开形成列表

在这里你需要仔细注意一下方程中的"||"中间有没有空格，如果有那你用的split()函数也得加上空格，即s1.split('| |')，因为你要让split()函数正确地找到分隔符

然后打印res就可以输出分割好的方程列表

## 求解

```py
from z3 import *

def solver_eng(fc):
    # 创建解释器对象
    solver = Solver()
    # 添加约束方程
    for i in range(len(fc)):
        solver.add(eval(fc[i])) #eval函数会将字符串形式的方程转换为z3模块能解析的方程
# 求解并转化为字符输出，得到flag

if solver.check() == sat:  # check()方法用来判断是否有解，sat(即satisify)表示满足有解
    ans = solver.model()  # model()方法得到解
    for i in v:
        print(chr(ans[i].as_long()), end='')
# 一般不会无解，如果无解八成是未知数变量的类型不符合，或约束方程添加错误
else:
    print("no ans!")
    
if __name__ == '__main__':
    # 设置方程，请用脚本将条件中的所有方程处理成列表，然后赋值给fc列表（这样你就不用一个一个方程慢慢去复制了）
    fc = []
    # 创建未知数变量
    v = [Int(f'v{i}') for i in range(0, len(fc))]
```

把这一整个列表复制下来，赋值给下面这个脚本的fc列表，直接运行就能出结果，这样脚本的通用性和便捷性大大提升了。
# libFuzzer && AFL

记录一些libfuzzer和afl fuzzer的学习记录，以及关于如何fuzz v8的一些问题，出发点是为信安作品赛做准备。参考的大量的文献和博客。
目前笔者对编译原理的认识还停留在parser，libfuzzer和afl，大量与代码覆盖率的有关的部分都和编译（例如插桩技术）有一定关系，希望学习这部分也能让笔者知道该补习的知识点。

## 基本概念

### 代码覆盖率及其相关概念[摘]

代码覆盖率是模糊测试中一个极其重要的概念，**使用代码覆盖率可以评估和改进测试过程，执行到的代码越多，找到bug的可能性就越大**，毕竟，在覆盖的代码中并不能100%发现bug，在未覆盖的代码中却是100%找不到任何bug的，所以本节中就将详细介绍代码覆盖率的相关概念。

**1. 代码覆盖率(Code Coverage)**

代码覆盖率是一种度量代码的覆盖程度的方式，也就是指源代码中的某行代码是否已执行；对二进制程序，还可将此概念理解为汇编代码中的某条指令是否已执行。其计量方式很多，但无论是GCC的GCOV还是LLVM的SanitizerCoverage，都提供函数（function）、基本块（basic-block）、边界（edge）三种级别的覆盖率检测，更具体的细节可以参考LLVM的[官方文档](https://clang.llvm.org/docs/SanitizerCoverage.html)。

**2. 基本块(Basic Block)**

缩写为BB，指一组顺序执行的指令，BB中第一条指令被执行后，后续的指令也会被全部执行，每个BB中所有指令的执行次数是相同的，也就是说一个BB必须满足以下特征：

- 只有一个入口点，BB中的指令不是任何**跳转指令**的目标。
- 只有一个退出点，只有最后一条指令使执行流程转移到另一个BB

[![13.jpg](https://image.3001.net/images/20190308/1552022202_5c81fabaca4bc.jpg!small)](https://image.3001.net/images/20190308/1552022202_5c81fabaca4bc.jpg)

将上面的程序拖进IDA，可以看到同样被划分出了4个基本块：

[![12.jpg](https://image.3001.net/images/20190308/1552022218_5c81faca1e0d8.jpg!small)](https://image.3001.net/images/20190308/1552022218_5c81faca1e0d8.jpg)

### 3. 边（edge） 

AFL的[技术白皮书](http://lcamtuf.coredump.cx/afl/technical_details.txt)中提到fuzzer通过插桩代码捕获边（edge）覆盖率。那么什么是edge呢？我们可以将程序看成一个控制流图（CFG），图的每个节点表示一个基本块，而edge就被用来表示在基本块之间的转跳。知道了每个基本块和跳转的执行次数，就可以知道程序中的每个语句和分支的执行次数，从而获得比记录BB更细粒度的覆盖率信息。

[![15.jpg](https://image.3001.net/images/20190308/1552022233_5c81fad93a797.jpg!small)](https://image.3001.net/images/20190308/1552022233_5c81fad93a797.jpg)

### 4. 元组（tuple）

具体到AFL的实现中，使用二元组(branch_src, branch_dst)来记录**当前基本块** + **前一基本块** 的信息，从而获取目标的执行流程和代码覆盖情况，伪代码如下：

```
cur_location = <COMPILE_TIME_RANDOM>;           //用一个随机数标记当前基本块
shared_mem[cur_location ^ prev_location]++;     //将当前块和前一块异或保存到shared_mem[]
prev_location = cur_location >> 1;              //cur_location右移1位区分从当前块到当前块的转跳
```

实际插入的汇编代码，如下图所示，首先保存各种寄存器的值并设置ecx/rcx，然后调用`__afl_maybe_log`，这个方法的内容相当复杂，这里就不展开讲了，但其主要功能就和上面的伪代码相似，用于记录覆盖率，放入一块共享内存中。

[![16.jpg](https://image.3001.net/images/20190308/1552022255_5c81faef97fc0.jpg!small)](https://image.3001.net/images/20190308/1552022255_5c81faef97fc0.jpg)

以上摘自[AFL漏洞挖掘技术漫谈（二）：Fuzz结果分析和代码覆盖率](https://www.freebuf.com/column/197672.html)



## libfuzzer

> 简介：LibFuzzer 是一个 in-process，coverage-guided，evolutionary 的模糊测试引擎，它是 LLVM 项目的一部分。LibFuzzer 和要被测试的库链接在一起，通过一个特殊的模糊测试进入点【目标函数】从而将产生fuzz输入数据给到被测试的库。fuzzer 会跟踪哪些代码区域已经测试过，然后在输入数据的语料库上产生变异，来最大化代码覆盖。代码覆盖的信息由 LLVM 的 SanitizerCoverage 插桩提供。

根据***[libfuzzer-workshop](https://github.com/Dor1s/libfuzzer-workshop)***的入门教程，逐步学习***libfuzzer***。

**实验要求**

- 2-3 hours of your time

- Linux-based OS

- C/C++ experience (nothing special, but you need to be able to read, write and compile C/C++ code)

- a recent version of 

  clang compiler. Distributions from package managers are too old and most likely won't work (the workshop called "modern", right?), you have two options:

  - checkout **llvm** repository and build it yourself. To make it easy, feel free to use [checkout_build_install_llvm.sh](https://github.com/Dor1s/libfuzzer-workshop/blob/master/checkout_build_install_llvm.sh)script, it has been tested on clean Ubuntu 16.04
  - a [VirtualBox VM](https://drive.google.com/file/d/0B19rvTqcOBfTZHZseDk3ZkNjWHc/view?usp=sharing) with working environment is available, credentials: `fuzzer:zeronights`

- `sudo apt-get install -y make autoconf automake libtool pkg-config zlib1g-dev`

Fuzzing experience is not required.





### An introduction to fuzz testing

> A software testing technique, often
> automated or semi-automated, that
> involves passing invalid, unexpected
> or random input to a program and
> monitor result for crashes, failed
> assertions, races, leaks, etc.	

-  Target
  ○ Consumes an array of bytes
  ○ Calls the code we want to test	
-  Fuzzer
  -  A tool that feed the target with different random inputs	
-  Corpus
    -   A set of valid & invalid inputs for the target
    -   Collected manually, by fuzzing, or by crawling

### An example of traditional fuzzing

介绍传统fuzz方式，通过生成样本输入程序来获得crashes（显然和现代的fuzz方式不同），本次实验会让我们实现一个传统的fuzzer。

> Take a look at [generate_testcases.py](generate_testcases.py) scripts. Then use
> `radamsa` to generate testcases from `seed_corpus`:

```bash
cd lessons/02
./generate_testcases.py
```

*generate_testcase.py*代码，从种子库中获取样本，通过radamsa进行变异生成样本。

```python
#!/usr/bin/env python2
import os
import random

WORK_DIR = 'work'

# Create work `directory` and `corpus` subdirectory.
if not os.path.exists(WORK_DIR):
  os.mkdir(WORK_DIR)																#创建工作目录

corpus_dir = os.path.join(WORK_DIR, 'corpus')
if not os.path.exists(corpus_dir):									#在work目录下创建corpus_dir目录
  os.mkdir(corpus_dir)

seed_corpus_filenames = os.listdir('seed_corpus')   #获取seed_corpus目录下文件名称列表

for i in xrange(1000):															#随机获取样例写入corpus
  random_seed_filename = random.choice(seed_corpus_filenames)
  random_seed_filename = os.path.join('seed_corpus', random_seed_filename)
  output_filename = os.path.join(WORK_DIR, 'corpus', 'testcase-%06d' % i)
  cmd = 'bin/radamsa "%s" > "%s"' % (random_seed_filename, output_filename)#变异样本
  os.popen(cmd)
```

> Verify number of files generated:

```bash
ls work/corpus/ | wc -l
1000
```

> Take a look at [run_fuzzing.py](run_fuzzing.py) script. Then run fuzzing:

```bash
tar xzf bin/asan.tgz
./run_fuzzing.py
```

```python
#!/usr/bin/env python2
import os
import subprocess

WORK_DIR = 'work'

#crash检测
def checkOutput(s):
  if 'Segmentation fault' in s or 'error' in s.lower():
    return False
  else:
    return True

corpus_dir = os.path.join(WORK_DIR, 'corpus')
corpus_filenames = os.listdir(corpus_dir)

#开始FUZZ
for f in corpus_filenames:
  testcase_path = os.path.join(corpus_dir, f)
  cmd = ['bin/asan/pdfium_test', testcase_path] #fuzz目标-> pdfium_test
  process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT) 
  output = process.communicate()[0]							#通过管道读取输出
  if not checkOutput(output): 									#检测crash
    print testcase_path
    print output
    print '-' * 80
```

> If you don't see any output, no crash has been found. Feel free to re-generate
> testcases many more times. Though it should take for a while to find a crash.

如果运行fuzz没有输出可以编写shell脚本多次生成样例进行fuzz

![Zqxv4b](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/Zqxv4b.png)


[pdfium]: https://pdfium.googlesource.com/pdfium/
[radamsa]: https://github.com/aoh/radamsa
[PDFium bugs]: https://bugs.chromium.org/p/chromium/issues/list?can=1&q=Type%3DBug-Security+component%3AInternals%3EPlugins%3EPDF+label%3Aallpublic+opened%3E2015-04-09&colspec=ID+Pri+M+Stars+ReleaseBlock+Component+Status+Owner+Summary+OS+Modified&x=m&y=releaseblock&cells=ids

**对v8的traditional fuzz test**

fuzz 包含漏洞版本的v8，分别创建in和out目录，在in中放入测试样例。

```python
#!/usr/bin/env python2
import os
import subprocess


def checkOutput(s):
  if 'Segmentation fault' in s or 'error' in s.lower():
    return False
  else:
    return True

corpus_dir = os.path.join('in')
corpus_filenames = os.listdir(corpus_dir)

i=0
for f in corpus_filenames:
  testcase_path = os.path.join(corpus_dir,f)
  cmd = ['./d8', testcase_path]
  process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
  output = process.communicate()[0]
  if not checkOutput(output):
    poc_name=os.path.join('out','poc'+str(i))
    cmd= 'cat "%s" > "%s"'%(testcase_path,poc_name)
    os.popen(cmd)
    print testcase_path
    print poc_name
    print output
    print '-' * 80
    
    i=i+1
```

测试poc

 ```javascript
let oobArray = [];
let maxSize = 1028 * 8;
Array.from.call(function() { return oobArray }, {[Symbol.iterator] : _ => ({ counter : 0,next() { let result = this.counter++; if (this.counter > maxSize) {oobArray.length = 0; return {done: true}; } else { return {value: result, done: false}; }} }) });
oobArray[oobArray.length - 1] = 0x41414141;
 ```

v8版本

 ```shell
git reset --hard 1dab065bb4025bdd663ba12e2e976c34c3fa6599
 ```

产生崩溃

```shell
$ ./easy-fuzz.py 
in/poc.js
out/poc0

#
# Fatal error in ../../src/objects/fixed-array-inl.h, line 96
# Debug check failed: index < this->length() (8223 vs. 0).
#
#
#
#FailureMessage Object: 0x7ffe7c6612c0
==== C stack trace ===============================

    /home/p0kerface/Documents/Browser/v8/v8/out.gn/x64.debug/./libv8_libbase.so(v8::base::debug::StackTrace::StackTrace()+0x1e) [0x7f6c2664669e]
   
...
    /home/p0kerface/Documents/Browser/v8/v8/out.gn/x64.debug/./libv8.so(v8::internal::Runtime_KeyedStoreIC_Miss(int, v8::internal::Object**, v8::internal::Isolate*)+0x107) [0x7f6c257ffdc7]
    [0xaba57d854a4]
Received signal 4 ILL_ILLOPN 7f6c26642961

--------------------------------------------------------------------------------
```

传统的fuzz方式（基于变异），即生成随机编译样本，输入到测试程序，检测是否出现crash。随机性非常大，测试的覆盖率很难有保证。早期的浏览器fuzz工具，都贯彻这种逻辑。

传统Fuzz浏览器的方式可以参考FreeBuf的这篇文章[从零开始学Fuzzing系列：浏览器fuzz工具探究之框架篇](https://www.freebuf.com/sectool/93130.html)



### Writing fuzzers (simple examples)

这部分是学习如何使用libfuzzer来编写一个fuzz，对我们的目标程序进行模糊测试。实验提供了三个目标函数作为FUZZ目标，我们将构造四个不同的Fuzzer对函数进行Fuzz实验。

**安装libfuuzer**

首先安装好`clang`编译工具，在libfuzzer-workshop/libFuzzer目录下运行build，编译libfuzzer.a

```
Fuzzer/build.sh
```

build的工作即将libFuzzer的.cpp文件进行编译，并且写入静态链接库libFuzzer.a，用户编写fuzzer的时候只需要`include`引用这个库即可调用libfuzzer的全部功能。

```shell
#!/bin/bash
LIBFUZZER_SRC_DIR=$(dirname $0)
CXX="${CXX:-clang}"
for f in $LIBFUZZER_SRC_DIR/*.cpp; do
  $CXX -g -O2 -fno-omit-frame-pointer -std=c++11 $f -c &
done
wait
rm -f libFuzzer.a
ar ru libFuzzer.a Fuzzer*.o
rm -f Fuzzer*.o
```



*实验中FUZZ的目标LIB*

***vulnerable_functions.h***

```c
// Copyright 2016 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");

#ifndef LESSONS_04_VULNERABLE_FUNCTIONS_H_
#define LESSONS_04_VULNERABLE_FUNCTIONS_H_

#include <stdint.h>
#include <stddef.h>
#include <cstring>

#include <array>
#include <string>
#include <vector>


bool VulnerableFunction1(const uint8_t* data, size_t size) {
  bool result = false;
  if (size >= 3) {
    result = data[0] == 'F' &&
             data[1] == 'U' &&
             data[2] == 'Z' &&
             data[3] == 'Z';
  }
  return result;
}

template<class T>
typename T::value_type DummyHash(const T& buffer) {
  typename T::value_type hash = 0;
  for (auto value : buffer)
    hash ^= value;

  return hash;
}

constexpr auto kMagicHeader = "ZN_2016";
constexpr std::size_t kMaxPacketLen = 1024;
constexpr std::size_t kMaxBodyLength = 1024 - sizeof(kMagicHeader);

bool VulnerableFunction2(const uint8_t* data, size_t size, bool verify_hash) {
  if (size < sizeof(kMagicHeader))
    return false;

  std::string header(reinterpret_cast<const char*>(data), sizeof(kMagicHeader));

  std::array<uint8_t, kMaxBodyLength> body;

  if (strcmp(kMagicHeader, header.c_str()))
    return false;

  auto target_hash = data[--size];

  if (size > kMaxPacketLen)
    return false;

  if (!verify_hash)
    return true;

  std::copy(data, data + size, body.data());
  auto real_hash = DummyHash(body);
  return real_hash == target_hash;
}


constexpr std::size_t kZn2016VerifyHashFlag = 0x0001000;

bool VulnerableFunction3(const uint8_t* data, size_t size, std::size_t flags) {
  bool verify_hash = flags & kZn2016VerifyHashFlag;
  return VulnerableFunction2(data, size, verify_hash);
}


#endif // LESSONS_04_VULNERABLE_FUNCTIONS_H_
```

### First_FUZZ

编写我们自己的fuzzer，我们只需要在LLVMFuzzerTestOneInput中调用待测函数即可。

所有的样本生成，崩溃检测，都是由Libfuzzer自动化完成。

>注释：（FuzzerInterface.h）
>
>//用户提供的必需目标函数。
>//以[Data，Data + Size）作为输入执行被测代码。
>// libFuzzer将使用不同的输入多次调用此函数。
>//必须返回0。

***first_fuzz.cc***

```c+=
bool VulnerableFunction1(const uint8_t* data, size_t size) {
  bool result = false;
  if (size >= 3) {
    result = data[0] == 'F' &&
             data[1] == 'U' &&
             data[2] == 'Z' &&
             data[3] == 'Z';
  }
  return result;
}
```

FUZZ的目标函数*VulnerableFunction1*，实际上我们已经在无数个关于libfuzzer的议题上见过他了。

```c++
#include <stdint.h>
#include <stddef.h>

#include "vulnerable_functions.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  VulnerableFunction1(data, size);
  return 0;
}
```

clang编译我们的fuzzer，注意-fsanitize-coverage=trace-pc-guard覆盖率参数，某些较早版本的clang是不包含的，笔者使用的clang4.0。编译过程需要 

```shell
clang++ -g -std=c++11 -fsanitize=address -fsanitize-coverage=trace-pc-guard \
    first_fuzzer.cc ../../libFuzzer/libFuzzer.a \
    -o first_fuzzer
```

关于编译参数的问题 [-Fsanitize =地址参数作用](https://www.dennisthink.com/2019/03/04/326/)-->用于边界检查 [honggfuzz漏洞挖掘技术原理分析](https://www.anquanke.com/post/id/181936)

创建一个种子目录，然后运行fuzzer

```shell
mkdir corpus1
./first_fuzzer corpus1
```

执行展示，产生一个越界读取的错误。

```shell
$ ./first_fuzzer 
INFO: Seed: 1699195943
INFO: Loaded 1 modules (34 guards): [0x771e90, 0x771f18), 
INFO: -max_len is not provided, using 64
INFO: A corpus is not provided, starting from an empty corpus
#0	READ units: 1
#1	INITED cov: 3 ft: 3 corp: 1/1b exec/s: 0 rss: 14Mb
#3	NEW    cov: 4 ft: 4 corp: 2/23b exec/s: 0 rss: 15Mb L: 22 MS: 2 ChangeBit-InsertRepeatedBytes-
#434	NEW    cov: 5 ft: 5 corp: 3/40b exec/s: 0 rss: 15Mb L: 17 MS: 3 ChangeBit-ChangeBit-InsertRepeatedBytes-
#111936	NEW    cov: 6 ft: 6 corp: 4/92b exec/s: 0 rss: 23Mb L: 52 MS: 5 ChangeByte-EraseBytes-ShuffleBytes-ChangeBinInt-InsertRepeatedBytes-
#213642	NEW    cov: 7 ft: 7 corp: 5/144b exec/s: 0 rss: 31Mb L: 52 MS: 1 ChangeByte-
=================================================================
==5024==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200019b8d3 at pc 0x0000005104f1 bp 0x7ffe38cd5660 sp 0x7ffe38cd5658
READ of size 1 at 0x60200019b8d3 thread T0
    #0 0x5104f0  (/home/p0kerface/Documents/Fuzzer/libfuzzer-workshop/lessons/04/first_fuzzer+0x5104f0)
    #1 0x510bd9  (/home/p0kerface/Documents/Fuzzer/libfuzzer-workshop/lessons/04/first_fuzzer+0x510bd9)
    #2 0x51ad63  (/home/p0kerface/Documents/Fuzzer/libfuzzer-workshop/lessons/04/first_fuzzer+0x51ad63)
    #3 0x51af94  (/home/p0kerface/Documents/Fuzzer/libfuzzer-workshop/lessons/04/first_fuzzer+0x51af94)
    #4 0x51b7cd  (/home/p0kerface/Documents/Fuzzer/libfuzzer-workshop/lessons/04/first_fuzzer+0x51b7cd)
    #5 0x51ba17  (/home/p0kerface/Documents/Fuzzer/libfuzzer-workshop/lessons/04/first_fuzzer+0x51ba17)
    #6 0x514594  (/home/p0kerface/Documents/Fuzzer/libfuzzer-workshop/lessons/04/first_fuzzer+0x514594)
    #7 0x5111e0  (/home/p0kerface/Documents/Fuzzer/libfuzzer-workshop/lessons/04/first_fuzzer+0x5111e0)
    #8 0x7f45741dd82f  (/lib/x86_64-linux-gnu/libc.so.6+0x2082f)
    #9 0x41c9c8  (/home/p0kerface/Documents/Fuzzer/libfuzzer-workshop/lessons/04/first_fuzzer+0x41c9c8)

0x60200019b8d3 is located 0 bytes to the right of 3-byte region [0x60200019b8d0,0x60200019b8d3)
allocated by thread T0 here:
    #0 0x50c0b0  (/home/p0kerface/Documents/Fuzzer/libfuzzer-workshop/lessons/04/first_fuzzer+0x50c0b0)
    #1 0x51aca9  (/home/p0kerface/Documents/Fuzzer/libfuzzer-workshop/lessons/04/first_fuzzer+0x51aca9)
    #2 0x51af94  (/home/p0kerface/Documents/Fuzzer/libfuzzer-workshop/lessons/04/first_fuzzer+0x51af94)
    #3 0x51b7cd  (/home/p0kerface/Documents/Fuzzer/libfuzzer-workshop/lessons/04/first_fuzzer+0x51b7cd)
    #4 0x51ba17  (/home/p0kerface/Documents/Fuzzer/libfuzzer-workshop/lessons/04/first_fuzzer+0x51ba17)
    #5 0x514594  (/home/p0kerface/Documents/Fuzzer/libfuzzer-workshop/lessons/04/first_fuzzer+0x514594)
    #6 0x5111e0  (/home/p0kerface/Documents/Fuzzer/libfuzzer-workshop/lessons/04/first_fuzzer+0x5111e0)
    #7 0x7f45741dd82f  (/lib/x86_64-linux-gnu/libc.so.6+0x2082f)

SUMMARY: AddressSanitizer: heap-buffer-overflow (/home/p0kerface/Documents/Fuzzer/libfuzzer-workshop/lessons/04/first_fuzzer+0x5104f0) 
Shadow bytes around the buggy address:
  0x0c048002b6c0: fa fa fd fd fa fa fd fd fa fa fd fa fa fa fd fa
  0x0c048002b6d0: fa fa fd fa fa fa fd fd fa fa fd fa fa fa fd fd
  0x0c048002b6e0: fa fa fd fd fa fa fd fd fa fa fd fd fa fa fd fd
  0x0c048002b6f0: fa fa fd fa fa fa fd fa fa fa fd fa fa fa fd fa
  0x0c048002b700: fa fa fd fa fa fa fd fa fa fa fd fa fa fa fd fa
=>0x0c048002b710: fa fa fd fd fa fa fd fd fa fa[03]fa fa fa fa fa
  0x0c048002b720: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c048002b730: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c048002b740: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c048002b750: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c048002b760: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==5024==ABORTING
MS: 4 CMP-ChangeBinInt-ChangeBit-CrossOver- DE: "\xff\xff\xff\xff\xff\xff\xff\xff"-; base unit: 5124a1022351fa049ef13f5ea5c789a692a508e6
0x46,0x55,0x5a,
FUZ
artifact_prefix='./'; Test unit written to ./crash-0eb8e4ed029b774d80f2b66408203801cb982a60
Base64: RlVa
```

复现crash

```shell
$ ASAN_OPTIONS=symbolize=1 ./first_fuzzer crash-0eb8e4ed029b774d80f2b66408203801cb982a60
```

***second_fuzz.cc***

```c++
constexpr auto kMagicHeader = "ZN_2016";
constexpr std::size_t kMaxPacketLen = 1024;
constexpr std::size_t kMaxBodyLength = 1024 - sizeof(kMagicHeader);

bool VulnerableFunction2(const uint8_t* data, size_t size, bool verify_hash) {
  if (size < sizeof(kMagicHeader))
    return false;

  std::string header(reinterpret_cast<const char*>(data), sizeof(kMagicHeader));

  std::array<uint8_t, kMaxBodyLength> body;

  if (strcmp(kMagicHeader, header.c_str()))
    return false;

  auto target_hash = data[--size];

  if (size > kMaxPacketLen)
    return false;

  if (!verify_hash)
    return true;

  std::copy(data, data + size, body.data());
  auto real_hash = DummyHash(body);
  return real_hash == target_hash;
}
```

第二个目标函数比较复杂，同样地编译second_fuzzer,不过最后是无法运行出crash的。

```c++
// Copyright 2016 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");

#include <stdint.h>
#include <stddef.h>

#include "vulnerable_functions.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  VulnerableFunction2(data, size, false);
  return 0;
}
```

如教程中所说，结果很无聊。

```
$ ./second_fuzzer corpus
INFO: Seed: 3205375691
INFO: Loaded 1 modules (35 guards): [0x77bec0, 0x77bf4c), 
Loading corpus dir: corpus
INFO: -max_len is not provided, using 64
#0	READ units: 4
#4	INITED cov: 4 ft: 4 corp: 2/21b exec/s: 0 rss: 13Mb
#12046	NEW    cov: 5 ft: 5 corp: 3/61b exec/s: 0 rss: 14Mb L: 40 MS: 2 CMP-InsertRepeatedBytes- DE: "ZN_2016"-
#2097152	pulse  cov: 5 ft: 5 corp: 3/61b exec/s: 1048576 rss: 171Mb
#4194304	pulse  cov: 5 ft: 5 corp: 3/61b exec/s: 1048576 rss: 328Mb
#8388608	pulse  cov: 5 ft: 5 corp: 3/61b exec/s: 1048576 rss: 494Mb
#16777216	pulse  cov: 5 ft: 5 corp: 3/61b exec/s: 0 rss: 495Mb
#33554432	pulse  cov: 5 ft: 5 corp: 3/61b exec/s: 0 rss: 495Mb
#67108864	pulse  cov: 5 ft: 5 corp: 3/61b exec/s: 2917776 rss: 496Mb
#134217728	pulse  cov: 5 ft: 5 corp: 3/61b exec/s: 1040447 rss: 496Mb
```

***third_fuzz.cc***

让我们将不同的值用作`verify_hash`对目标API的进行模糊测试。

```c++
#include "vulnerable_functions.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  bool verify_hash_flags[] = { false, true };

  for (auto flag : verify_hash_flags)
    VulnerableFunction2(data, size, flag);
  return 0;
}
```

运行third_fuzzer`$ ./third_fuzzer.cc corpus/`

![屏幕快照2020-aws](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/屏幕快照 2020-aws.png)

但是运行依然没有结果，cov达到了24但是仍然没有结果。注意提示`INFO: -max_len is not provided, using 64`，而我们的VulnerableFunction2函数kMaxPacketLen参数达到了1024。

我们添加参数-max_len=1024,重新运行`./third_fuzzer corpus/ -max_len=1024`,很快就出结果了。

 ```
$ ./third_fuzzer corpus/ -max_len=1024
INFO: Seed: 302963015
INFO: Loaded 1 modules (37 guards): [0x77bf00, 0x77bf94), 
Loading corpus dir: corpus/
#0	READ units: 5
#5	INITED cov: 24 ft: 24 corp: 3/61b exec/s: 0 rss: 13Mb
=================================================================
==56188==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fffb9a42468 at pc 0x0000004dc815 bp 0x7fffb9a41eb0 sp 0x7fffb9a41660
WRITE of size 1023 at 0x7fffb9a42468 thread T0

 ```

***Fourth_fuzzer***

最后一个目标API其实是对之前漏洞函数的封装

> *Note*: imagine that there are more than two different `flags` values possible. If your fantasy needs inspiration, please take a look at possible values of `flags` and `mode` arguments of standard [open()](http://man7.org/linux/man-pages/man2/open.2.html) function.

```c++
constexpr std::size_t kZn2016VerifyHashFlag = 0x0001000;

bool VulnerableFunction3(const uint8_t* data, size_t size, std::size_t flags) {
  bool verify_hash = flags & kZn2016VerifyHashFlag;
  return VulnerableFunction2(data, size, verify_hash);
}
```

这里我们使用libfuzzer提供的data为flag提供随机量。

```c++
#include "vulnerable_functions.h"

#include <functional>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::string data_string(reinterpret_cast<const char*>(data), size);
  auto data_hash = std::hash<std::string>()(data_string);

  std::size_t flags = static_cast<size_t>(data_hash);
  VulnerableFunction3(data, size, flags);
  return 0;
}
```

CRASH!

```
$ ./fourth_fuzzer corpus/ -max_len=1024
INFO: Seed: 2570988747
INFO: Loaded 1 modules (42 guards): [0x77bec0, 0x77bf68), 
Loading corpus dir: corpus/
#0	READ units: 5
#5	INITED cov: 26 ft: 26 corp: 3/61b exec/s: 0 rss: 13Mb
#6	NEW    cov: 27 ft: 27 corp: 4/101b exec/s: 0 rss: 14Mb L: 40 MS: 1 ChangeBinInt-
=================================================================
==56570==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffd526dc068 at pc 0x0000004dc915 bp 0x7ffd526dbab0 sp 0x7ffd526db260
```

**FUZZ是如何测试目标函数的**

运行fuzz，调用FuzzerMain.cpp，将LLVMFuzzerTestOneInput作为参数写入FuzzerDriver。

```c++
#include "FuzzerDefs.h"

extern "C" {
// This function should be defined by the user.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
}  // extern "C"

int main(int argc, char **argv) {
  return fuzzer::FuzzerDriver(&argc, &argv, LLVMFuzzerTestOneInput);
}
```

FuzzerDriver的定义

```c++
int FuzzerDriver(int *argc, char ***argv, UserCallback Callback);
```

### HeartBleed

通过libfuzzer来找到openSSL中Heartbleed(心脏滴血)漏洞 (CVE-2014-0160).

编译openssl，需要使用clang作为编译器，并且增加检查的选项。

```
tar xzf openssl1.0.1f.tgz
cd openssl1.0.1f/

./config
make clean
make CC="clang -O2 -fno-omit-frame-pointer -g -fsanitize=address -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-gep,trace-div" -j$(nproc)
```

构建我们的Fuzzer

```c++
// Copyright 2016 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <assert.h>
#include <stdint.h>
#include <stddef.h>

#ifndef CERT_PATH
# define CERT_PATH
#endif

SSL_CTX *Init() {
  SSL_library_init();
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();
  SSL_CTX *sctx;
  assert (sctx = SSL_CTX_new(TLSv1_method()));
  /* These two file were created with this command:
      openssl req -x509 -newkey rsa:512 -keyout server.key \
     -out server.pem -days 9999 -nodes -subj /CN=a/
  */
  assert(SSL_CTX_use_certificate_file(sctx, CERT_PATH "server.pem",
                                      SSL_FILETYPE_PEM));
  assert(SSL_CTX_use_PrivateKey_file(sctx, CERT_PATH "server.key",
                                     SSL_FILETYPE_PEM));
  return sctx;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static SSL_CTX *sctx = Init();
  SSL *server = SSL_new(sctx);
  BIO *sinbio = BIO_new(BIO_s_mem());
  BIO *soutbio = BIO_new(BIO_s_mem());
  SSL_set_bio(server, sinbio, soutbio);
  SSL_set_accept_state(server);
  BIO_write(sinbio, data, size);
  SSL_do_handshake(server);
  SSL_free(server);
  return 0;
}
```



```
clang++ -g openssl_fuzzer.cc -O2 -fno-omit-frame-pointer -fsanitize=address \
    -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-gep,trace-div \
    -Iopenssl1.0.1f/include openssl1.0.1f/libssl.a openssl1.0.1f/libcrypto.a \
    ../../libFuzzer/libFuzzer.a -o openssl_fuzzer
```

运行fuzzer

```
./openssl_fuzzer ./corpus1/
```

跑出crash

```
INFO: Seed: 2343292669
INFO: Loaded 1 modules (33435 guards): [0xc38d30, 0xc5979c), 
Loading corpus dir: ./corpus/
INFO: -max_len is not provided, using 64
INFO: A corpus is not provided, starting from an empty corpus
#0	READ units: 1
#1	INITED cov: 1510 ft: 395 corp: 1/1b exec/s: 0 rss: 23Mb
#3	NEW    cov: 1516 ft: 426 corp: 2/34b exec/s: 0 rss: 24Mb L: 33 MS: 2 ShuffleBytes-InsertRepeatedBytes-
...
#43645	NEW    cov: 1583 ft: 703 corp: 32/1489b exec/s: 7274 rss: 369Mb L: 61 MS: 4 CopyPart-CMP-ShuffleBytes-ShuffleBytes- DE: "\xa4\x03\x00\x00"-
=================================================================
==59625==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x629000009748 at pc 0x0000004dc132 bp 0x7fff878b7860 sp 0x7fff878b7010
READ of size 55013 at 0x629000009748 thread T0

```

### C-ARES（CVE-2016-5180）

c-ares是一个异步解析程序库，它适用于需要执行DNS查询而不阻塞的应用程序。这个实验我本地没有构建成功。

编译c-ares

```
tar xzvf c-ares.tgz
cd c-ares

./buildconf
./configure CC="clang -O2 -fno-omit-frame-pointer -g -fsanitize=address -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-gep,trace-div"
make CFLAGS=
```

构建运行fuzzer

```c++
#include <ares.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  unsigned char *buf;
  int buflen;
  std::string s(reinterpret_cast<const char *>(data), size);
  ares_create_query(s.c_str(), ns_c_in, ns_t_a, 0x1234, 0, &buf, &buflen, 0);
  ares_free_string(buf);
  return 0;
}
```

```
cd ..
clang++ -g c_ares_fuzzer.cc -O2 -fno-omit-frame-pointer -fsanitize=address \
    -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-gep,trace-div \
    -Ic-ares c-ares/.libs/libcares.a \
    ../../libFuzzer/libFuzzer.a -o c_ares_fuzzer
mkdir corpus1
./c_ares_fuzzer corpus1
```

其实这里的fuzzer还是有点不太懂，libfuzzer这些输入定义都是怎么弄的。还得看源代码（心酸

### Final

***最后一个实验要求我们学会如何使用chromium自带的fuzzer（基于libfuzzer），以及我们自己学会编写libfuzzer。***

编译v8自带的fuzzer工具，v8是如何构建的在后面我们再详细讲解。

```
gn gen out/libfuzzer '--args=use_libfuzzer=true is_asan=true ' --check
$ ninja -C out/libfuzzer v8_simple_json_fuzzer
```

运行fuzzer

```
$ out/libfuzzer/v8_simple_json_fuzzer  corpus/
```

报错提示，malloc失败。

```
Failed to allocate 9223372036854775807 bytes
```

没有运行成功，也没有testcase能够使用。原因还未知，网上也基本没有这方面的实验。。。报错如下(并不是全部，在我添加了其他编译选项之后，还有很多其他奇怪的报错)

报错的源代码可以在/test/fuzzer/fuzzer.cc中找到，当然笔者依然不确定这是什么情况。传入参数为单个文件没问题，但是传入目录就因为malloc失败，目前还无法理解这种设计。simple_fuzzer应该只是框架而已，，内部函数都没有编写完善，需要我们自己去编写这个fuzzer。。。

```c++
  uint8_t* data = reinterpret_cast<uint8_t*>(malloc(size));
  if (!data) {
    fclose(input);
    fprintf(stderr, "Failed to allocate %zu bytes\n", size);
    return 1;
  }
```

之后可以考虑用chromiumn里面自带的libfuzzer来测试一下，v8这个可能比较simple???

***埋个坑***

## libfuzzer和AFL fuzzer的优缺点[摘]

libFuzzer 优点在于针对某一个函数和组件的Fuzzing 非常有效.使用libFuzzer 通常不需要测试用例就可以直接运行(如果需要Fuzzing 图形库和网络库时往往需要一些特殊的值和关键字那么就需要引入关键字字典来Fuzzing )缺点是需要阅读源代码找到数据解析的入口点再编写测试用例(参考libFuzzer Fuzzing -ares)在EFuzzing 大型项目里往往会耗时比较多

AFL的优点在于只需要数据样本即可执行很多的开源项目会自带使用程序(有些库没有提供自带的使用程序就需要自己重新写一个程序入口点a-tuz调用)编译完成之后.只需要按照使用程序的命令和测试样本带入到af-fuz2就可以跑了非常方便测试缺点在于没有好的样本会导致代码覆盖率不高不容易跑到更深入的Crash 

总结一下libFuzzer 适合Fuzzing 局部代码，afl适合Fuzzing 整个项目。libFuzzer 可以自己生成测试数据，afl则需要依赖数据样本。

---

## 如何构建V8的Fuzzer

如何为v8构建一个fuzzer，目前主流的构建方法是通过libfuzzer或者afl fuzzer，chromium源代码中包含了fuzzer的demo可以参考。

### GN是如何构建v8的

[参考链接](https://zhuanlan.zhihu.com/p/86249625) 

*GN*是一种元构建系统，生成*Ninja*构建文件（*Ninja* build files）

编译v8的一种简单的方式，是通过编写好的python脚本执行gen，自动化生成build.gn和args.gn文件,具体操作见[v8 base](https://migraine-sudo.github.io/2020/02/15/v8/)。实际上通过gen来生成toolchain也是非常轻松的。

**使用gn gen创建build.gn**

out/Default ：是生成目录，我们的配置文件和可执行文件都会在这里

--args : 是编译参数，参数会写入配置文件gn.args中。

gn args --list out/Default/：查看所有可选参数

```
gn gen out/Default --args='is_clang=true is_debug=true use_sanitizer_coverage=true sanitizer_coverage_flags="trace-pc-guard"' # 参数会写入gn.args中
ninja -C out/Default d8 #编译
```

###需要了解的几个关键词

***Sanitizer***

一些动态测试工具，使用‘编译时’架构，来检测发现程序运行时的错误，包括

- [ASan](https://clang.llvm.org/docs/AddressSanitizer.html)（又名AddressSanitizer）
- [LSan](https://clang.llvm.org/docs/LeakSanitizer.html)（又名LeakSanitizer）
- [MSan](https://clang.llvm.org/docs/MemorySanitizer.html)（又名MemorySanitizer）
- [UBSan](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)（又名UndefinedBehaviorSanitizer）
- [TSan](https://clang.llvm.org/docs/ThreadSanitizer.html)（又名ThreadSanitizer）

对于这些工具，适配最好的编译器是Clang。

*使用方法（[ASan](https://clang.llvm.org/docs/AddressSanitizer.html#addresssanitizer)）*

编译时，添加编译选项***-fsanitize=address***，AddressSanitizer运行时库就会被链接到可执行程序中。

***如何为v8的编译添加Asan***

只需要在`gn gen out/xxx` 时，添加参数`is_asan=true`即可

### 方案一：libfuzzer

使用clang对v8进行编译？

 [使用clang编译chromiumn](https://blog.csdn.net/zxc024000/article/details/79912720)

[ gn gen编译](https://blog.csdn.net/Vincent95/article/details/78499883)

[gn入门](https://www.cnblogs.com/xl2432/p/11844943.html)

使用clang对v8进行编译，并且增加覆盖率检测函数。

使用gn gen创建build.gn

```
gn gen out/Default --args='is_clang=true is_debug=true use_sanitizer_coverage=true sanitizer_coverage_flags="trace-pc-guard"' # 参数会写入gn.args中
ninja -C out/Default d8
```

查看所有可选参数

```
gn args --list out/Default/
```

编译v8的fuzzer，可以编译的选项见out/Default/obj目录或者build.gn。fuzzer的源码都在test/fuzzer中。

```
ninja -C out/Default v8_fuzzers
```

fuzzer.cc代码如下

```c++
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

int main(int argc, char* argv[]) {
  if (LLVMFuzzerInitialize(&argc, &argv)) {
    fprintf(stderr, "Failed to initialize fuzzer target\n");
    return 1;
  }

  if (argc < 2) {
    fprintf(stderr, "USAGE: %s <input>\n", argv[0]);
    return 1;
  }

  FILE* input = fopen(argv[1], "rb");

  if (!input) {
    fprintf(stderr, "Failed to open '%s'\n", argv[1]);
    return 1;
  }

  fseek(input, 0, SEEK_END);
  size_t size = ftell(input);
  fseek(input, 0, SEEK_SET);

  uint8_t* data = reinterpret_cast<uint8_t*>(malloc(size));
  if (!data) {
    fclose(input);
    fprintf(stderr, "Failed to allocate %zu bytes\n", size);
    return 1;
  }

  size_t bytes_read = fread(data, 1, size, input);
  fclose(input);

  if (bytes_read != static_cast<size_t>(size)) {
    free(data);
    fprintf(stderr, "Failed to read %s\n", argv[1]);
    return 1;
  }

  int result = LLVMFuzzerTestOneInput(data, size);

  free(data);

  return result;
}
```

***What is next?***

将v8编译为一个静态库？然后编译时调用 v8.h

使用libfuzzer对某个函数进行fuzz时，又如何能保证构建正确的Array对象。

了解一下BUILD.gn文件，里面似乎有惊喜

[Javascript引擎漏洞检测方法综述](http://www.doc88.com/p-8819153939756.html)

[如何正确地使用v8嵌入到我们的C++应用中](https://zhuanlan.zhihu.com/p/86416857)

[V8引擎在C++程序中使用简介](https://www.cnblogs.com/wolfx/p/5920141.html)

需要了解v8的C++编程，然后再编写针对某个函数的libfuzzer。暂时留坑。

### 方案二：Dharma+afl

通过语法生成，结合AFL的覆盖率检测，实现针对整体的fuzz。

***ret2团队的思路如下***

*lighthouse+lcov–>feedback*
*dharma–>语法生成*

***要添加更多混淆的工具***

radamsa

---

***产生语法***

[用DHARMA实现FUZZ LOGICS](https://xz.aliyun.com/t/4045)

解决了语法问题，接下来，考虑如何控制覆盖率（或者是否可以和libfuzzer/alf这样能够插桩的fuzzer进行整合）

**使用[afl](https://paper.seebug.org/841/)作为后端**

首先必须对v8进行插桩，gen编译添加参数use_afl=true。

这样能够让afl-gcc/afl-clang作为后端来编译v8，能够提供代码覆盖率。

```
use_afl
    Current value (from the default) = false
      From //build/config/sanitizers/sanitizers.gni:83

    Compile for fuzzing with AFL.
```

[参考:Ubuntu下编译pdfium](https://www.jianshu.com/p/8bb348ba8d61) 

[nodejs深入学习系列之v8基础篇](https://zhuanlan.zhihu.com/p/86249625)

***使用afl-gcc/afl-clang编译***

*方法一：修改args.gn中的参数*

配置参数，ninja和传统的make方式不同，不能通过***./configure CC=xxxx***来修改编译工具。

v8使用***build.gn***文件来进行配置，存在一个参数***use_afl***，我们将这个选项设置为true并将配置写入args.gn。

命令如下

```
#配置并且编译v8，使用afl-gcc编译
gn gen out/libfuzzer '--args=use_afl=true is_asan=true optimize_for_fuzzing = true ' --check
$ ninja -C out/libfuzzer d8

#查看所有的可用参数
gn args --list out/Default/
```

![WkojxW](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/WkojxW.png)

当然，如果我们仅仅下载了v8源码，需要在***chromium***项目文件中找到afl的[支持文件](https://chromium.googlesource.com/chromium/src/+/refs/heads/master/third_party/afl/),并且放到third_party/afl目录下，关键文件是Build.gn，src中的afl可以用自己的源代码。***PS：添加use_afl参数的程序会自动在程序本地编译一个afl-fuzz，不过如果想在整个系统中使用afl-fuzz，记得在src中执行make指令！***`make CFLAGS="-std=c11 -D_GNU_SOURCE"`

一开始总是check_binary提示没有插桩，后来发现可能是afl编译的锅，读了afl里面的README之后，添加了编译参数`CFLAGS="-std=c11 -D_GNU_SOURCE`，重新编译afl。如果没有插桩，只能用dirty模式运行(-n)，没有覆盖率的检查。

*方法二：直接修改toolchain*

我们也可以尝试自己去修改toolchain。首先，我们需要去看一个GN是如何构建v8程序的。

我们在***build/config/BUILDCONFIG.gn***中找到了is_clang选项（另外，is_clang在缺省的条件下，默认为true）。

```
  # See comments in build/toolchain/cros/BUILD.gn about board compiles.
  if (is_clang) {
    _default_toolchain = "//build/toolchain/linux:clang_$target_cpu"
  } else {
    _default_toolchain = "//build/toolchain/linux:$target_cpu"
  }
```

GN并不提供toolchain，所有的编译选项实际上都是由我们规定的，只需要找到配置文件即可。我们发现这里的itoolchain指向了***build/toolchain/linux***目录。不幸的是我并没有找到clang的具体编译器，所以我修改了gcc编译器为afl-gcc。需要注意是，为了使用gcc作为默认工具链，需要在args.gn中添加参数is_clang=false。

```
#args.gn
optimize_for_fuzzing = true
is_clang = false
```



```diff
gcc_toolchain("x64") {
-  cc = "gcc"
-  cxx = "g++"
+  cc = "afl-gcc"
+  cxx = "afl-g++"

  readelf = "readelf"
  nm = "nm"
  ar = "ar"
  ld = cxx

  # Output linker map files for binary size analysis.
  enable_linker_map = true

  toolchain_args = {
    current_cpu = "x64"
    current_os = "linux"
    is_clang = false
  }
}
```

当修改了build/toolchain/linux/Build.gn下的gcc_toolchain，但是ninja运行报错无法找到AFL的as，需要添加AFL_PATH。

![CUNZNV](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/CUNZNV.png)

终端运行(具体地址要根据您的安装目录)，添加环境变量。

`$ export AFL_PATH=/path/to/afl/src/`

例如笔者机器`export AFL_PATH=/home/p0kerface/Documents/Browser/v8/v8/third_party/afl/src/`

当然方案二最终并没有编译成功，在afl-g++编译obj/v8_base/code-stub-assembler.o的时候发生了一些问题。

***一些报错与解决***

不知道是不是我的v8版本和chromium的最新版的区别，并不存在no_defalut_deps这个参数。所以需要在BUILD.gn文件中讲其注释掉。

![Sh1mVY](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/Sh1mVY.png)

![pdYHjh](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/pdYHjh.png)

***检测是否成功***

查看二进制文件编译使用的编译工具。似乎我们这里默认会是clang编译的，否则Sanitizer会罢工不干。

```
objdump -s --section .comment 二进制文件
```

如果插桩失败，如果直接运行`afl-fuzz -i afl-in/ -o afl-out/ d8`就会显示没有插桩，提示用-n参数，不过这样就完全是无目的fuzz了。

![0cKxyQ](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/0cKxyQ.png)

在FUZZ过程中，AFL需要fork多个进程，fuzz v8这样体量的代码，默认分配50MB显然是不够de。所以需要加上-m参数。报错如下。

![jPw2MN](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/jPw2MN.png)

运行成功，覆盖率检测运作正常。（不过我使用虚拟机跑的，速度感人）

`$ afl-fuzz -m 9999 -i corpus/ -o afl-out/  out/Default/d8`

![GPVyT4](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/GPVyT4.png)

给出我最终的args.gn文件

```
optimize_for_fuzzing = true
is_clang=true
use_afl =true
is_asan = true
v8_current_cpu="x64"
```

## Source

[chromium source](https://chromium.googlesource.com/chromium/src/+/refs/heads/master)

[AFL](https://github.com/google/AFL)

## 扩展阅读

[libfuzzer教程](https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md)

[Art of Fuzzing](https://www.youtube.com/watch?v=QNrecApGtJA&list=PLnGQRUoLDBQq8jN7_S_9G-JL9ct3CgURu)

[Fuzzbook](https://www.fuzzingbook.org/html/00_Table_of_Contents.html)

[泉哥honggfuzz漏洞挖掘技术系列](https://bbs.pediy.com/thread-247954.htm)

[使用libFuzzer fuzz Chrome V8入门指南](https://blog.csdn.net/weixin_33919941/article/details/90355732)

[c++ - 使用Clang构建V8并发出LLVM IR](https://www.ojit.com/article/579358)

[honggfuzz漏洞挖掘技术原理分析](https://www.anquanke.com/post/id/181936)

[使用Afl-fuzz (American Fuzzy Lop) 进行fuzzing测试](https://blog.csdn.net/youkawa/article/details/76405468)

[Fuzzing with Code Coverage By Example](https://www.ise.io/wp-content/uploads/2019/11/cmiller_toorcon2007.pdf)

[集群模糊测试](https://google.github.io/clusterfuzz/reference/glossary/#corpus-pruning)

[Chromium Fuzzing with libfuzzer](https://iami.xyz/Fuzzing-Tutorial-02/)



# 附录：

生成产生crash的dharma语法模板

```javascript
%const% VARIANCE_MIN := 1
%const% VARIANCE_MAX := 20

%%% ######################################################
%section% := value

Num :=
    %range%(1-10);

Page :=
    1024

next :=
	{!result!=1.1;this.counter++;if (this.counter > !maxSize!) {!array!.length=0;return {done: true};}else {return {value:!result!, done: false};}}

iterator :=
    {counter:0 , next(){+next+}}

array :=
    {[Symbol.iterator]:_=>(+iterator+)}


function :=
    call

args1 :=
    function(){return !array!}

args2 :=
    {return }

Part1 :=
    //!array!;
    //!maxSize!;
    !array![array.length-1]=0x41414141;
    
Part2 :=
    Array.from.+function+(+args1+,+array+);
%%% ######################################################
%section% := variable
array :=
    let @array@=[];

maxSize :=
    let @maxSize@=+Page+*+Num+;

result :=
    let @result@=1.1;
    let @result@=1.2;
%%% ######################################################
%section% := variance
main :=
    +Part1+
    +Part2+
```

fuzzer Demo

```python
import subprocess
import os
import re
import time
#Demo
#fuzz our targets
#$python3 fuzzer.py

###################################################
def crash(filename):
	f=open(filename,'r')
	crash=f.read()
	poc_name=str(hash(str(time.time())))
	poc_dir="crash/"
	poc=open(poc_dir+poc_name,'w+')
	poc.write(crash)
	print("crash hash : "+poc_name)
###################################################
def generate(num):
	grammars_path=os.path.join("grammars")
	grammars_filenames=os.listdir(grammars_path)
	for f in grammars_filenames:
		grammars_file=""
		grammars_file=grammars_path+"/"+f
		print ("grammars ="+grammars_file)
		os.system("cd corpus && dharma -grammars ../"+grammars_file+" -storage . -count "+str(num))
	print ("[+] generate cases ...\n")

###################################################
def fuzz():
	corpus_path=os.path.join("corpus")
	corpus_filenames=os.listdir(corpus_path)
	process=subprocess.Popen("whereis d8",shell=True,stdin=subprocess.PIPE, stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
	pwd=str(process.communicate()[0])
	
	test_casepath=re.search("/.*"+"d8",pwd).group(0)
	test_casepath='/home/p0kerface/Documents/Browser/v8/v8/out/Default/d8'
	#test_case="d8"
	#os.chdir(corpus_path)
	for f in corpus_filenames:
		corpus_file=corpus_path+"/"+f
		cmd=test_casepath+" "+corpus_file
		print ("[+]test_case ["+f+"]")
		process=subprocess.Popen(cmd,shell=True,stdin=subprocess.PIPE, stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
		#subprocess.Popen(cmd,shell=True)
		output=str(process.communicate()[0])
		if  'core dumped' or 'error 'in output:
			print("="*20+"find crash "+"="*20)
			print(output)
			crash(corpus_file)
			print("="*50)
###################################################			



generate(100)
fuzz()
```


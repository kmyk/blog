---
category: blog
layout: post
redirect_from:
    - "/blog/2017/02/06/values-above-stack-is-not-preserved/"
date: "2017-02-07T00:06:07+09:00"
tags: [ "stack", "binary", "signal" ]
---

# 割り込みによるスタックの上方の値の予期せぬ書き換えについて

CTFやbrainfuck golfではスタックの進む先の空間を普通の領域として利用することがある。
この領域が勝手に書き変わる場合について、具体例としてsignalによる割り込みを思い付いたため検証した。
結論としては、signalが飛び自分で設定したhandlerが走ると壊れることがあるということである。

## 設定

以下のようなC言語のプログラムを考える。
整数を入力させをれをそのまま出力するだけのプログラムである。
ただし、スタックの進む先のアドレスに対し、そこへ一瞬だけ書き込んで読み出す。

``` c
int main(void) {
    int x, *p;
    p = &x - 0x10;
    scanf("%d", &x);
    *p = x;
    x = *p;
    printf("%d\n", x);
}
```

これは間違いなく規格違反だろうが、実際のところ何事もなかったかのように動く。

``` sh
$ gcc --version
gcc (Ubuntu 5.4.1-2ubuntu1~16.04) 5.4.1 20160904
Copyright (C) 2015 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

$ gcc a.c
$ ./a.out
1234
1234
```

signalが絡むとこのようなプログラムが失敗しうることを確認する。

## 確認

先に通常の場合を確認する。

この上の例をdisassembleすると以下のようになる。
`*p = x;`から`x = *p;`の間には特に他の命令はないため、ほぼ間違いなく値は保存されると言ってよいだろう。
この間には`p`を触らない命令なら他に何を入れてもよいが、もちろん関数を`call`するなどすれば値は壊れうる。

``` asm
00000000004005f6 <main>:
  4005f6:       55                      push   rbp
  4005f7:       48 89 e5                mov    rbp,rsp
  4005fa:       48 83 ec 20             sub    rsp,0x20
  4005fe:       64 48 8b 04 25 28 00    mov    rax,QWORD PTR fs:0x28
  400605:       00 00 
  400607:       48 89 45 f8             mov    QWORD PTR [rbp-0x8],rax
  40060b:       31 c0                   xor    eax,eax
  # p = &x - 0x10;
  40060d:       48 8d 45 ec             lea    rax,[rbp-0x14]
  400611:       48 83 e8 40             sub    rax,0x40
  400615:       48 89 45 f0             mov    QWORD PTR [rbp-0x10],rax
  # scanf("&d", &x);
  400619:       48 8d 45 ec             lea    rax,[rbp-0x14]
  40061d:       48 89 c6                mov    rsi,rax
  400620:       bf f4 06 40 00          mov    edi,0x4006f4
  400625:       b8 00 00 00 00          mov    eax,0x0
  40062a:       e8 b1 fe ff ff          call   4004e0 <__isoc99_scanf@plt>
  # *p = x;
  40062f:       8b 55 ec                mov    edx,DWORD PTR [rbp-0x14]
  400632:       48 8b 45 f0             mov    rax,QWORD PTR [rbp-0x10]
  400636:       89 10                   mov    DWORD PTR [rax],edx
  # x = *p;
  400638:       48 8b 45 f0             mov    rax,QWORD PTR [rbp-0x10]
  40063c:       8b 00                   mov    eax,DWORD PTR [rax]
  40063e:       89 45 ec                mov    DWORD PTR [rbp-0x14],eax
  # printf("%d\n", x);
  400641:       8b 45 ec                mov    eax,DWORD PTR [rbp-0x14]
  400644:       89 c6                   mov    esi,eax
  400646:       bf f7 06 40 00          mov    edi,0x4006f7
  40064b:       b8 00 00 00 00          mov    eax,0x0
  400650:       e8 6b fe ff ff          call   4004c0 <printf@plt>
  # return 0;
  400655:       b8 00 00 00 00          mov    eax,0x0
  40065a:       48 8b 4d f8             mov    rcx,QWORD PTR [rbp-0x8]
  40065e:       64 48 33 0c 25 28 00    xor    rcx,QWORD PTR fs:0x28
  400665:       00 00 
  400667:       74 05                   je     40066e <main+0x78>
  400669:       e8 42 fe ff ff          call   4004b0 <__stack_chk_fail@plt>
  40066e:       c9                      leave  
  40066f:       c3                      ret    

```

## signal

disassemble結果としてはまったく問題なくても値が保存されない例として、signalが考えられる。
つまり、`*p = x;`から`x = *p;`の間で何らかのsignalが飛びそのhandlerが呼ばれた場合、このhandlerは値を壊しうる。

狙った位置でsignalを飛ばすためbusy waitを入れ、検証コードは以下のようになった。

``` c
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

void func(void) {
    long long x;
    long long *p;
    p = &x - 0x20;
    scanf("%lld", &x);
    *p = x;
    while (x --) ; // busy wait
    x = *p;
    printf("%lld\n", x);
}

void handler(int sig) {
    char buf[4096];
    memset(buf, 0, sizeof(buf));
}

int main(void) {
    signal(SIGALRM, handler);
    alarm(4);
    func();
    return 0;
}
```

実際、実行すると以下のようになる。
signalによる割り込みが発生した場合では、結果が壊れていることが分かる。

``` sh
$ echo 123456789 | time ./a.out
123456789
0.25s 1424KB
```

``` sh
$ echo 12345678999 | time ./a.out
0
22.47s 1424KB
```

ただし、手元の環境では、`SIGSTOP`や`SIGCONT`のdefault handlerではstackの破壊は起きなかった。

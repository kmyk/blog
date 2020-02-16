---
category: blog
layout: post
date: "2017-02-14T01:29:16+09:00"
tags: [ "elf", "linker" ]
---

# ELFの.interp sectionを書き換えてその挙動を確認してみる

ELFにおいて、共有libraryのlinkはOSでなくheader内で指定されてlinkerが行う。
このlinkerを指定する文字列を書き換え、その挙動を確認した。

## 準備

ELFのprogram headerのtypeとして、`PT_INTERP`がある。
これは単一のbinary中に高々$1$つまで存在し、そのsegment内の文字列としてinterpreterを指定する。
interpreterが指定されているとき、本体がloadされるより先にそのinterpreterがloadされる。
用途としては共有libraryの準備であり、その場合interpreterが本体プログラムをloadする。
INTERP segmentはたいてい`.interp` sectionを唯一のsegmentとして含む(ただしsection名は必ずしも`.interp`である必要はない)。

準備として、普通のプログラムを用意する。
例え陽にlibcの関数を呼んでいなかったとしても(例えば`__libc_start_main`などのために) libcは動的linkされていて`.interp` sectionが存在する。
今回、pathは`/lib64/ld-linux-x86-64.so.2`であった。

``` c
#include <stdio.h>
int main(void) {
    printf("Hello, world!\n");
    return 0;
}
```

``` sh
$ gcc helloworld.c -o helloworld

$ ./helloworld
Hello, world!

$ objdump -s helloworld | grep interp -A 2
Contents of section .interp:
 400238 2f6c6962 36342f6c 642d6c69 6e75782d  /lib64/ld-linux-
 400248 7838362d 36342e73 6f2e3200           x86-64.so.2. 
```

## 上書き

interpreterとして指定するプログラムの処理内容は(指定するだけなら)なんでもよい。

この例では`interrupted`と表示して終了するプログラムを使用する。`Hello, world!`の代わりにこれが表示されれば成功である。

``` sh
#include <stdio.h>
int main(int argc, char **argv) {
    printf("interrupted\n");
    return 1;
}
```

ただし再帰的にinterpreterを要求するのは許されないようで、静的linkする必要がある。

``` sh
$ gcc -static interp.c -o interp
```

適当に`.interp`を編集する。null終端の文字列が認識されるので、後ろにゴミを残してもよい。

``` sh
$ objdump -s helloworld | grep interp -A 1
Contents of section .interp:
 400238 2f746d70 2f696e74 65727000 6e75782d  /tmp/interp.nux-
 400248 7838362d 36342e73 6f2e3200           x86-64.so.2.
```

このような準備の元で、`./helloworld`を叩くと`Hello, world!`でなく`interrupted`と表示される。
これは期待される挙動である。

``` sh
$ cp interp /tmp

$ ./helloworld
interrupted
```

## 他

引数とかもちゃんと渡ってきてたりする。(ld-linuxは`argv = NULL`でも仕事をするのでこれを読んでいるのではない。)

``` c
$ cat interp.c
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    for (int i = 0; i < argc; ++ i) {
        printf("argv[%d] : %s\n", i, argv[i]);
    }
    scanf("%*c");
}
```

``` sh
$ ./helloworld foo bar
argv[0] : ./helloworld
argv[1] : foo
argv[2] : bar
^Z

$ ps aux | grep '[h]elloworld\|[i]nterp'
user     10136  0.0  0.0   1120     8 pts/18   T    00:57   0:00 ./helloworld foo bar

$ gdb -p `pidof helloworld`
...
gdb-peda$ vmmap
Start              End                Perm	Name
0x00400000         0x004c9000         r-xp	/tmp/interp
0x006c8000         0x006cb000         rw-p	/tmp/interp
0x006cb000         0x006cd000         rw-p	mapped
0x01510000         0x01533000         rw-p	[heap]
0x00007fff59965000 0x00007fff59987000 rw-p	[stack]
0x00007fff599f6000 0x00007fff599f8000 r--p	[vvar]
0x00007fff599f8000 0x00007fff599fa000 r-xp	[vdso]
0xffffffffff600000 0xffffffffff601000 r-xp	[vsyscall]
```

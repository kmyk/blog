---
category: blog
layout: post
date: "2017-02-15T10:09:51+09:00"
title: "auxiliary vectorをdumpしてみる"
tags: [ "elf", "auxiliary-vector", "linux" ]
---

プログラムがそのentry pointから実行を始めるとき、そのstack上には`argv`や`envp`の中身の文字列が積まれている。
これらの他にauxiliary vectorという値が積まれている。
通常はlibcの[getauxval](https://linuxjm.osdn.jp/html/LDP_man-pages/man3/getauxval.3.html)関数を用いて取得するが、プログラム開始時のstackの構造への理解のため直接これを出力させた。
なお、同様の出力は`LD_SHOW_AUXV`環境変数を用いても得られる。

## 結果

### 64bit

``` c
$ gcc a.c
$ ./a.out
AT_SYSINFO_EHDR : 0x7ffe0e5ef000
AT_HWCAP : 0xbfebfbff
AT_PAGESZ : 0x1000
AT_CLKTCK : 0x64
AT_PHDR : 0x400040
AT_PHENT : 0x38
AT_PHNUM : 0x9
AT_BASE : 0x7f4ad46ee000
AT_FLAGS : (nil)
AT_ENTRY : 0x4004c0
AT_UID : 0x3e8
AT_EUID : 0x3e8
AT_GID : 0x3e8
AT_EGID : 0x3e8
AT_SECURE : (nil)
AT_RANDOM : 0x7ffe0e5e8d59
AT_EXECFN : "./a.out"
AT_PLATFORM : "x86_64"
AT_NULL : (nil)
```

`AT_EXECFN`等の参照先は`envp`のそれらと同様にstack中に存在する。

### 32bit

``` c
$ sed -i~ s/Elf64/Elf32/g aux.c
$ gcc -m32 a.c
$ ./a.out
AT_SYSINFO : 0xf7795be0
AT_SYSINFO_EHDR : 0xf7795000
AT_HWCAP : 0xbfebfbff
AT_PAGESZ : 0x1000
AT_CLKTCK : 0x64
AT_PHDR : 0x8048034
AT_PHENT : 0x20
AT_PHNUM : 0x9
AT_BASE : 0xf7796000
AT_FLAGS : (nil)
AT_ENTRY : 0x8048370
AT_UID : 0x3e8
AT_EUID : 0x3e8
AT_GID : 0x3e8
AT_EGID : 0x3e8
AT_SECURE : (nil)
AT_RANDOM : 0xfff1938b
AT_EXECFN : "./a.out"
AT_PLATFORM : "i686"
AT_NULL : (nil)
```

## 実装

手元の環境(Ubuntu 16.04)では、`Elf*_auxv_t`は`/usr/include/elf.h`に、`AT_*`の定義は`/usr/include/x86_64-linux-gnu/bits/auxv.h`または`/usr/include/linux/auxvec.h`にあった。

``` c
#include <stdlib.h>
#include <stdio.h>
#include <elf.h>
#include <x86_64-linux-gnu/bits/auxv.h> // <linux/auxvec.h>
const char *strauxvtype(uint64_t a_type) {
    switch (a_type) {
        case AT_NULL:           return "AT_NULL";
        case AT_IGNORE:         return "AT_IGNORE";
        case AT_EXECFD:         return "AT_EXECFD";
        case AT_PHDR:           return "AT_PHDR";
        case AT_PHENT:          return "AT_PHENT";
        case AT_PHNUM:          return "AT_PHNUM";
        case AT_PAGESZ:         return "AT_PAGESZ";
        case AT_BASE:           return "AT_BASE";
        case AT_FLAGS:          return "AT_FLAGS";
        case AT_ENTRY:          return "AT_ENTRY";
        case AT_NOTELF:         return "AT_NOTELF";
        case AT_UID:            return "AT_UID";
        case AT_EUID:           return "AT_EUID";
        case AT_GID:            return "AT_GID";
        case AT_EGID:           return "AT_EGID";
        case AT_CLKTCK:         return "AT_CLKTCK";
        case AT_PLATFORM:       return "AT_PLATFORM";
        case AT_HWCAP:          return "AT_HWCAP";
        case AT_FPUCW:          return "AT_FPUCW";
        case AT_DCACHEBSIZE:    return "AT_DCACHEBSIZE";
        case AT_ICACHEBSIZE:    return "AT_ICACHEBSIZE";
        case AT_UCACHEBSIZE:    return "AT_UCACHEBSIZE";
        case AT_IGNOREPPC:      return "AT_IGNOREPPC";
        case AT_SECURE:         return "AT_SECURE";
        case AT_BASE_PLATFORM:  return "AT_BASE_PLATFORM";
        case AT_RANDOM:         return "AT_RANDOM";
        case AT_HWCAP2:         return "AT_HWCAP2";
        case AT_EXECFN:         return "AT_EXECFN";
        case AT_SYSINFO:        return "AT_SYSINFO";
        case AT_SYSINFO_EHDR:   return "AT_SYSINFO_EHDR";
        case AT_L1I_CACHESHAPE: return "AT_L1I_CACHESHAPE";
        case AT_L1D_CACHESHAPE: return "AT_L1D_CACHESHAPE";
        case AT_L2_CACHESHAPE:  return "AT_L2_CACHESHAPE";
        case AT_L3_CACHESHAPE:  return "AT_L3_CACHESHAPE";
        default: { char *p = malloc(32); sprintf(p, "(%d)", a_type); return p; }
    }
}
Elf64_auxv_t *auxv_from_envp(char **envp) {
    char **p = envp;
    while (*p) ++ p;
    ++ p;
    return (Elf64_auxv_t *)p;
}
int main(int argc, char **argv, char **envp) {
    Elf64_auxv_t *auxv = auxv_from_envp(envp);
    while (1) {
        printf("%s : ", strauxvtype(auxv->a_type));
        printf(auxv->a_type == AT_EXECFN || auxv->a_type == AT_PLATFORM ? "\"%s\"\n" : "%p\n", auxv->a_un.a_val);
        if (auxv->a_type == AT_NULL) break;
        ++ auxv;
    }
    return 0;
}
```

## 参考

-   [ドライバーその他　補足説明　プロセス実行時のスタック - ０から作るソフトウェア開発](http://softwaretechnique.jp/OS_Development/Supplement/Binary/elf_stack.html)
-   [Man page of GETAUXVAL](https://linuxjm.osdn.jp/html/LDP_man-pages/man3/getauxval.3.html)

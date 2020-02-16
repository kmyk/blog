---
layout: post
alias: "/blog/2017/03/06/pragyanctf-2017-answer-to-everything/"
date: "2017-03-06T00:03:34+09:00"
tags: [ "ctf", "pragyan-ctf", "guessing", "western-lowland-gorilla" ]
---

# Pragyan CTF 2017: Answer to Everything

問題文は以下。

>   Shal has got a binary. It contains the name of a wise man and his flag. He is unable to solve it.
>   Submit the flag to unlock the secrets of the universe.

カテゴリは`Binary Exploits`であるが与えられるバイナリには脆弱性などは存在せず、単に以下のようなコードをそのままコンパイルしたもの。
また`main.exe`という名前であるがPEでなくELFであった。

``` c
int main() {
    int n;
    printf("Gimme: ");
    scanf("%d", &n);
    if (n == 42) {
        puts("Cipher from Bill\n"
            "Submit without any tags\n"
            "#kdudpeh");
    } else {
        puts("YOUSUCK");
    }
    return 0;
}
```

上記の情報だけからflagに辿り着かなければならない。以下のようにすればflagが得られる:

1.  怪しい文字列 `#kdudpeh` から始める
2.  `Submit without any tags`とあるので`#`を除去
3.  rot$23$して`harambe` (ゴリラ、特に西ローランドゴリラのある個体の名前: <https://en.wikipedia.org/wiki/Killing_of_Harambe>)
4.  問題文の冒頭`Shal has got a binary.`なので`Shal`つまりSHA1して`31a0d851ea10ad886ad4e99ed05892de06998ab9`

よって flag: `pragyanctf{31a0d851ea10ad886ad4e99ed05892de06998ab9}`

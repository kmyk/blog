---
category: blog
layout: post
title: "brainfuckにおけるコンパイル時処理"
date: 2015-12-25T00:19:25+09:00
tags: [ "brainfuck", "compile-time" ]
---

brainfuckのコンパイル時の処理を実現する方法の紹介です。
なんらかの言語のコンパイル時にbrainfuckを処理するという話ではありません。

しかしbrainfuckは定数代入にすら$O(a+b)$かかる言語ですので、コンパイル時の処理といっても現状では限定的な条件分岐のみです。

<!-- more -->

## 具体例

brainfuckの処理系をホストするpythonのバージョンを、brainfuckを用いてかつbrainfuckの実行時より上のレベルで取得し、出力する例です。

``` sh
$ cat check-python.bf
++++++++++[>+++++<-]
>[>++>++>++>++>++>++>+>++> >++>++>+>+>+>++>++>++>++>++>++<<<<<<<<<<<<<<<<<<<<-]
+++++[>>+++>>>++>+++>---->++++> >+>++>---->->>++>++>+>+++>++++>----<<<<<<<<<<<<<<<<<<<<-]
>+>+>--->>++>++>++>++ >++[-][<[-]>>->->>>+<<<<<-] >+++>++>++>->>>+>->+>+>
[.<] <[.<]

$ export LANG=ja_JP.sjis

$ python2 interpreter.py check-python.bf
Python2, plz update

$ python3 interpreter.py check-python.bf
Python3, ok
```

-   `check-python.bf`: [download](/blog/2015/12/25/compile-time-programming-in-brainfuck/check-python.bf)
    -   ブログシステムの都合上、上で示しているコードを直接コピーしても動かないので注意してください。

### 環境

``` python
$ python2 --version
Python 2.7.11

$ python3 --version
Python 3.5.1

$ cat interpreter.py
#PyBrain
from sys import*
def f(u,c,k):
 while(c[-2]>=k)*u:
  j,u='[]><+-,.'.find(u[0]),u[1:]
  b=(j>=0)*(1-j%2*2);c[-2]+=b*(j<2)
  while b*c[c[-1]]and j<1:f(u,c,k+1);c[-2]+=1
  b*=c[-2]==k;c[[-1,c[-1],-3][int(j/2)-1]]+=b
  if(j==6)*b:c[c[-1]]=ord(stdin.read(1))
  if(j>6)*b:stdout.write(chr(c[c[-1]]))
f(open(argv[1]).read(),[0]*30003,0)
```

`interpreter.py`は<http://esolangs.org/wiki/User:Boothby#PyBrain>をpython3でも動くよう修正したものです。[^1]

## 解説

見ての通り、文字コード魔法です。
エンコーディングによって1文字となるbyte列が変わるためにこうなります。
性質上、主にはLL製の処理系でしか機能しないでしょう。
またエンコーディングに関して中途半端な処理をしている処理系では動かないかもしれません。

応用としては、`EOF`が`0`の処理系と`-1`の処理系の両方に対応したいときとかに使えたりするかもしれません。
また、使う価値があるかは別として、他の言語のソースコードでも同様のことができます。

---

[^1]: この技法が使えてかつ簡単にインストールできそうなコンパイラ($\ne$ インタプリタ)を見つけられればよかったのですが、<esolangs.org>にある一覧にはなかったので諦めました。

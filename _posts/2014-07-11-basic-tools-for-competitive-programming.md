---
category: blog
layout: post
date: 2014-07-11T01:38:41+09:00
tags: [ "kyopro", "gdb", "gprof", "c++", "c", "shell" ]
---

# 競技プログラミング用の基本的な道具の使い方

友人達のために

-   gdb
-   gprof
-   redirect
-   diff

<!-- more -->

# gdb
`GNU debugger`

``` sh
$ clang++ -g a.cpp
```

のように、`-g`optionを付けてdebug用の情報を埋め込みコンパイルしたバイナリを

``` sh
   $ gdb a.out
```

と引数に起動する

種々の情報の後に以下のようなプロンプトが現れ、ここにコマンドを入力していく

``` plain
(gdb)
```

## run / start

``` plain
(gdb) run
```

とすると、バイナリの実行が始まる

``` plain
(gdb) run < sample.in
```

とすれば、入力を指定できる

`start`で起動した場合、`main`関数でbreakする

## list
``` plain
(gdb) list
```

現在停止位置周辺のソースコードを表示する

`l`, `li`, `lis`等でも反応する 他のコマンドでも同様である

## break

``` plain
(gdb) break 42
(gdb) break solve
```

などと行や関数を指定しbreak pointを設定する  
実行中、指定した部分に到達したとき実行が一時停止する

## print

``` plain
(gdb) print ary
$1 = {1, 2, 3, 4, 0 <repeats 252 times>}

```

指定した変数の中身を表示する

## watch

指定した変数の中身が変更された時、停止する

``` plain
(gdb) watch x
Hardware watchpoint 1: x
(gdb) run
Starting program: /path/to/a.out
Hardware watchpoint 1: x

Old value = 0
New value = 1
0x000000000040055c in func (n=3) at a.c:4
4       int func(int n) { return x = n % 2; }
```

## next / step

``` plain
(gdb) next
(gdb) step
```

現在位置の次の行を実行し停止する  
`step`は関数呼び出しの内側へ入り込んでいく

## cont

``` plain
(gdb) cont
```

実行を再開する 次のbreak pointまで停止しない

## up / down

``` plain
(gdb) up
(gdb) down
```

stackを上がったり下がったり

## backtrace
どのような関数呼び出しを経て現在位置に至ったかを表示する  
segvした後に呼ぶと、何処でこけたか判明する

``` plain
(gdb) backtrace
#0  fact (n=0) at a.c:3
#1  0x000000000040054b in fact (n=1) at a.c:3
#2  0x000000000040054b in fact (n=2) at a.c:3
#3  0x000000000040054b in fact (n=3) at a.c:3
#4  0x000000000040054b in fact (n=4) at a.c:3
#5  0x0000000000400566 in main () at a.c:6
```



# gprof

``` sh
$ clang++ -pg a.cpp
```

のように、`-pg`optionを付けてprofile用の情報を埋め込みコンパイルする  
manを見ると、末尾の`g`は`-g`とは違うようだ

そうしてできたバイナリを実行するとプロファイル結果が出力されるので、その後`gprof`を呼び出すとその結果を表示してくれる

``` sh
$ ./a.out #=> gmon.out
$ gprof a.out
```


# redirect

入力したい文字列をクリップボードでなくファイルに書き出し、

``` sh
$ cat test.in | ./a.out
```

とすると、ファイルの中身を自動で入力に渡してくれる

``` sh
$ ./a.out < test.in > test.out
```

等とすれば、さらに出力をファイルに書き出すこともできる


# diff

``` sh
$ cat foo
abc
def
xyz
$ cat bar
and
def
xyzzy
```

のように、ファイルに格納された比較対象を、

``` sh
$ diff foo bar
1c1
< abc
---

# 競技プログラミング用の基本的な道具の使い方
> and
3c3
< xyz
---

# 競技プログラミング用の基本的な道具の使い方
> xyzzy
```

と`diff`に渡すと、行ごとの比較をしてくれる

## more

``` sh
$ cat sample.in | ./a.out | diff - sample.out
$ diff <(./a.out < sample.in) sample.out
```

等とすると便利

``` sh
$ diff out out
```

しないように注意

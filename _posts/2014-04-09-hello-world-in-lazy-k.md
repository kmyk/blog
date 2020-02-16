---
category: blog
layout: post
date: 2014-04-09T00:19:29+09:00
tags: [ "lazyk", "helloworld", "ski", "combinator" ]
---

# lazy kでhello world書いた

-   "hello world"
-   9000byteぐらい
-   できるだけ自力で書いた
-   CPPを使用 (`gcc -E`)
-   [ラムダ計算について調べた](/blog/2014/04/05/lambda-calculus-for-great-good/)のを有効活用した
-   楽しい

<!-- more -->

## Lazy K is 何
-   [翻訳:プログラミング言語Lazy\_K](http://legacy.e.tir.jp/wiliki?%cb%dd%cc%f5%3a%a5%d7%a5%ed%a5%b0%a5%e9%a5%df%a5%f3%a5%b0%b8%c0%b8%ecLazy_K)
-   [404 Blog Not Found:Math \- 言語はどこまで小さくなれるか \- \(unlambda\|iota\|jot\) のすすめ](http://blog.livedoor.jp/dankogai/archives/51524324.html)
    -   ここのpatchあてて-fpermissiveしたらcompile通った
-   すごそう
-   かっこいい


## 入出力
-   プログラムに引数として標準入力が与えられ、返り値が標準出力に出る
-   つまり `getContents >>= (pure . main) >>= putStr`
-   ただし文字列はチャーチ数のスコットエンコーディングのリスト
    -   [ラムダ計算で代数的データ型を表現する方法 - @syamino はてなダイアリー](http://d.hatena.ne.jp/syamino/20120524/p1)


---

# lazy kでhello world書いた


## ignore\_input

``` c
#define ignore_input k
```

-   code頭に置いて、入力を無視する
-   `k PROGRAM INPUT -> PROGRAM`


## 簡単な関数
``` c
#define id (skk)
#define true k
#define false (ki)
#define zero false
#define one id
```

何とか書ける


## car cdr / head tail
-   `car list = list true`
-   `cdr list = list false`

しかし

```
\ x y . y x
```

が書けない

とりあえず文字列を持ってきて`true`/`false`を試してみる

[Hello worldプログラムの一覧 # Lazy_K - Wikipedia](https://ja.wikipedia.org/wiki/Hello_world%E3%83%97%E3%83%AD%E3%82%B0%E3%83%A9%E3%83%A0%E3%81%AE%E4%B8%80%E8%A6%A7#Lazy_K)

``` c
#define helloworld ``s``si`k```s``sss```s``s`ks`ssi``ss`ki``s`ksk`k``s``si`k` \
    ``ss``s``ss`ki``ss```ss`ss``ss`ki``s`ksk`k``s``si`k```s``si``ss``ss`ki``` \
    ss`s``sss``ss`ki``s`ksk`k``s``si`k```s``si``ss``ss`ki```ss`s``sss``ss`ki` \
    `s`ksk`k``s``si`k```ss``s``sss``ss```ss`ss``ss`ki``s`ksk`k``s``si`k```ss` \
    `ss``s``sss``s``sss``ss`ki``s`ksk`k``s``si`k```s``ss```ssi``ss`ki``ss`ki` \
    `s`ksk`k``s``si`k```s``si``ss``s``sss``ss`ki``ss```ss``ssi``ss`ki``s`ksk` \
    k``s``si`k```ss``s``sss``ss```ss`ss``ss`ki``s`ksk`k``s``si`k```ss``ss``ss \
    ``ss``s``sss``ss```ss`ss``ss`ki``s`ksk`k``s``si`k```s``si``ss``ss`ki```ss \
    `s``sss``ss`ki``s`ksk`k``s``si`k```s``ss`ki``ss```ss`ss``ss`ki``s`ksk`k`` \
    s``si`k```ss```ss`ss``ss`ki``s`ksk`k`k```sii```sii``s``s`kski
```

``` c
ignore_input (helloworld false)
##=> ello, world
```

動く


## T[]変換
-   救世主現る
-   [コンビネータ論理 # T\[\] 変換について - Wikipedia](http://ja.wikipedia.org/wiki/%E3%82%B3%E3%83%B3%E3%83%93%E3%83%8D%E3%83%BC%E3%82%BF%E8%AB%96%E7%90%86#S-K\_basis.E3.81.AE.E5.AE.8C.E5.85.A8.E6.80.A7)
-   わりと簡単な`lambda式 -> skiコンビネータ`の変換
-   eta簡約もすると短くなる `(s (k X) i) -> X`


## \ x y. y x
wikipediaの例と同じだけど、自分でも変換する

``` c
#define rev (s (k (s i)) k)
```

## car / cdr
`\ x y. y x` ができたので作れるように

``` c
#define car (rev true)
#define cdr (rev false)
```

``` c
ignore_input (cdr helloworld)
##=> ello, world
```

## succ
-   `\ n f x. f (n f x)` も変換
-   結構頑張る

``` c
#define succ (s (k (s (s (k s) k))) (s (s (k s) k) (k i)))
```

## cons
-   `succ`だけあっても使えないので`cons`
-   lazy-kはスコットエンコーディング
-   `\ x y z . z x y`

``` c
#define cons (s (s (k s) (s (k k) (s (k s) (s (k (s i)) (s (k k) i))))) (k (s (k k) i)))
```

``` c
#define cons (s (s (k s) (s (k k) (s (k s) (s (k (s i)) k)))) (k k))
##=> Iello, world
```

## 演算
```
plus = \ m n. m succ n
mult = \ m n f. m (n f)
pow = \ m n n (mult m) one # 不要
```

``` c
#define plus (s (s (k s) (s (k k) (s i (k succ)))) (k i))
#define mult (s (s (k s) (s (k k) (s (k s) k))) (k i))
#define pow (s (s (k s) (s (k (s i)) (s (k k) mult))) (k (k one)))
```

-   手作業で丁寧に変換

## hello world

### 出力すべき数を確認する

``` sh
$ ghc -e 'print $ map ord "hello world"'
[104,101,108,108,111,32,119,111,114,108,100]

$ ghc -e 'print $ map (($ "") . showIntAtBase 2 intToDigit . ord) "hello world"'
["1101000","1100101","1101100","1101100","1101111","100000","1110111","1101111","1110010","1101100","1100100"]
```

### 数字を定義
``` c
#define two (s (s (k s) k) i) # 無駄な変換
#define double (mult two)
#define four (double two)
#define eight (double four)
#define sixteen (double eight)
#define thirtytwo (double sixteen)
#define sixtyfour (double thirtytwo)
#define eof (pow four four)
```

-   lazy-kは`256`をもって`eof`とする
-   2進数万歳
-   2は変換しておいた

### 完成

``` scheme
ignore_input
(cons (plus sixtyfour (plus thirtytwo eight)) # h
(cons (plus sixtyfour (plus thirtytwo (plus four one))) # e
(cons (plus sixtyfour (plus thirtytwo (plus eight four))) # l
(cons (plus sixtyfour (plus thirtytwo (plus eight four))) # l
(cons (plus sixtyfour (plus thirtytwo (plus eight (plus four (plus two one))))) # o
(cons thirtytwo # ' '
(cons (plus sixtyfour (plus thirtytwo (plus sixteen (plus four (plus two one))))) # w
(cons (plus sixtyfour (plus thirtytwo (plus eight (plus four (plus two one))))) # o
(cons (plus sixtyfour (plus thirtytwo (plus sixteen two))) # r
(cons (plus sixtyfour (plus thirtytwo (plus eight four))) # l
(cons (plus sixtyfour (plus thirtytwo four)) # e
(cons eof k))))))))))))
```

``` sh
$ gcc -E a.lazy.cpp > a.lazy && echo hoge | ./lazy a.lazy
hello world
```


---

# lazy kでhello world書いた

2014/04/11
:    `two`の定義が抜けてたので修正

---
category: blog
layout: post
redirect_from:
    - "/blog/2015/06/09/introduction-to-categorical-programming-language-cpl/"
date: 2015-06-10T02:41:57+09:00
tags: [ "cpl", "esolang", "category" ]
---

# 圏論プログラミング言語CPL入門

面白かったので入門記事を書きました。haskellの知識を仮定しますが圏論の知識は一切要求しません。

## 言語概要

-   圏論に基づく
    -   データは射として表す
    -   関数は射あるいは羃対象として表す
-   Turing完全でない
    -   計算は必ず停止する
-   作者は日本人

<!-- more -->

## 環境導入

[haskellによる実装](http://hackage.haskell.org/package/CPL)が存在するのでこれを用います。`cabal`を用いて以下ですべて済みます。

``` sh
$ cabal install CPL
```

起動するには`cpl`と叩きます。

``` sh
$ cpl
Categorical Programming Language (Haskell version)
version 0.0.7

Type help for help

cpl> 
```

引数にファイルを与えるとそれを実行します。中身を標準入力から流しこんだかのようなかの挙動をします。読み込んだ後replに入るオプション`-i`もあります。

``` sh
$ cpl a.cpl
```

## データ型定義

cplでは、データ型を定義することができます。以下のように書きます。

```
right object 関手(型変数1, ..., 型変数n) with 仲介射 is
    自然変換1 : 関手 -> 型
    自然変換2 : 関手 -> 型
    ...
    自然変換n : 関手 -> 型
end object ;
```

```
left object 関手(型変数1, ..., 型変数n) with 仲介射 is
    自然変換1 : 型 -> 関手
    自然変換2 : 型 -> 関手
    ...
    自然変換n : 型 -> 関手
end object ;
```

`right object`宣言で作られるデータ型を右データ型と呼び、`left object`宣言で作られるデータ型を左データ型と呼びます。圏論臭い単語が並んでいますが、以下のように思えば問題ありません。

-   右データ型とは直積型
-   左データ型とは直和型
-   関手とは型構築子
-   仲介射は、
    -   右データ型の場合、値構築子
    -   左データ型の場合、パターンマッチと畳み込み
-   自然変換は、
    -   右データ型の場合、フィールドを取り出す関数
    -   左データ型の場合、値構築子

### 例

例としては、以下のようになります。それぞれ、haskellで言うところのタプル`(,)`とリスト`[]`を定義しています。

```
right object prod(A,B) with pair is
    pi1: prod -> A
    pi2: prod -> B
end object ;
```

```
left object list(A) with fold is
    nil: 1 -> list
    cons : prod(A, list) -> list
end object ;
```

## 計算する

CPLではデータも関数も全て射で表されます。射とは関数だと思ってよいです。

### 射

射は以下からなります。

-   恒等射 `I`
-   射`f`,`g`による合成射 `g.f`
-   自然変換 `a`
-   射`x`,`y`,...により定まる仲介射 `f(x,y,...)`
-   射`x`,`y`,...を関手`f`で写したもの `f(x,y,...)`

恒等射`I`及び射の合成`.`は言語組み込みですが、他は自分で定義します。自然変換はそのまま射ですが、仲介射は引数を埋めて始めて射となります。

### データ

データもまた射です。一般に、型`A`から型`B`への関数を考えたとき、型`A`の要素がただひとつしかないなら、その関数は型`B`の要素と同一視してよさそうです。cplはこの考えを用いてデータを表現します。

そのようなデータ型は、以下のように、自然変換を持たない右データ型`1`として作れます。

```
right object 1 with ! is
end object ;
```

ここで仲介射`!`は型`*a -> 1`、つまり任意の型から`1`への射です。

また、このようなデータ型を終対象と呼びます。終対象は複数定義できますが、その性質によりお互いに変換できるので、ただひとつ存在していると見なせます。

### 実行

以下のコマンドは、それぞれ式の計算結果、式の型を表示します。

```
simp full データ ;
```

```
show 射 ;
```

`simp full`にはデータ型、つまり任意の型`*a`あるいは終対象`1`からの射を与える必要があります。

また、射/関手を定義することができます。

```
let 識別子(引数, ...) = 射 ;
```

再帰的な定義はできないので、単なる記述の補助でしかありません。

### 例

例として、後者関数`pred`を挙げます。

```
right object 1 with ! is
end object ;

left object nat with pr is
    o: 1 -> nat
    s: nat -> nat
end object ;

right object prod(A,B) with pair is
    pi1: prod -> A
    pi2: prod -> B
end object ;

let pred = pi2.pr(pair(o,o),pair(s.pi1,pi1)) ;

show pred ;
simp full pred.s.s.s.o ;
```

```
...
> simp full pred.s.s.s.o
s.s.o
    : 1 -> nat
```

自然数とは`o`と`s`からなるものだと定義され、`o`,`s`はそれぞれ`0`,`+1`に相当します。`3`は`s.s.s.o`と表します。仲介射`pr`は左データ型なので畳み込みであり、原始帰納法[^1]になっています。つまり、`pr(f,g).n`とすると、`f`の`n`回合成と`g`の合成`f.f.....f.g`の意味です。

`prod`はタプルです。haskellとの対応としては以下のようになります。

-   `pi1`は`fst`
-   `pi2`は`snd`
-   `pair(f,g)`は`f &&& g`
-   `prod(f,g)`は`f *** g`

純粋にアルゴリズムとして、対`(0,0)`から始めて、`(a,b)`を`(a+1,a)`にする操作を`n`回したとき、その第2要素は`n-1`であり、この通りに書いてあります。

### しくみ

cplの計算の実行は、変換規則に従った変換により行なわれます。

変換規則は、

```
show object データ型 ;
```

とすることで見ることができます。例えば`nat`であれば、

```
(LEQ1): pr(f0,f1).o=f0
(LEQ2): pr(f0,f1).s=f1.pr(f0,f1)
...
```

のような規則を持ちます。これはまさに`f0`に続けて`f1`を`n`回繰り返すということを示しています。


## 関数空間

重要なデータ型として関数空間や巾と呼ばれるものがあります。これはクロージャを表します。以下のように定義されます。

```
right object exp(A,B) with cur is
    ev: prod(exp, A) -> B
end object ;
```

仲介射`cur`はcurry化を表し、`show object exp`すると実際にそうであることが分かります。

```
f0: prod(*a,*b) -> *c
-------------------------
cur(f0): *a -> exp(*b,*c)
```

自然変換`ev`は値の適用を表し、型は以下のとおりです。

```
ev: prod(exp(*a,*b),*a) -> *b
```

cplには値の束縛の概念がないため、使いたい値は使う場所まで運ばねばなりません。高階関数を用いる際だけでなく、原始帰納法`pr`の内側などの直接値を運べない場所から外部の値を参照する時などにも関数空間が活躍します。

### 例

```
let add = ev.prod(pr(cur(pi2),cur(s.ev)),nat) ;
let mul = ev.prod(pr(cur(o.!),cur(add.pair(ev,pi2))),nat) ;
```

```
let first(f) = prod(f,I) ;
let swap = pair(pi2,pi1) ;
let filter = ev.first(fold(cur(nil.!),cur(ev.pair(if(cur(cons.pi2),cur(pi2.pi2)).ev.pair(pi2,pi1.pi1),pair(pi1.pi1,ev.pair(pi2.pi1,pi2)))))).swap ;
```

## tips

### newtype

```
right object newtype(A) with wrap is
    unwrap : newtype -> A
end object ;
```

とすると、newtype宣言のようなものができます。多少複雑な関数でも、型の力で殴れば意外と書けますので活用しましょう。

### 穴

```
let func(hole1, hole2, ...) = ... hole1 ... hole2 ... ;
```

のようにすると、埋めるべき型を確認しながら書けます。便利。

実際に実行すると以下のようになります。

```
> let fib(hole1,hole2) = hole2.pr(pair(s.o,o),pair(hole1,pi1))
hole1: prod(nat,nat) -> nat  hole2: prod(nat,nat) -> *a
-------------------------------------------------------
fib(hole1,hole2): nat -> *a
```

### vim

vimにcplのindent/highlightの設定がなかったので作りました。<https://github.com/kmyk/cpl.vim>にあります。

```
NeoBundle 'solorab/cpl.vim'
```

## よく定義されるデータ型

```
right object 1 with ! is
end object;

left object 0 with !! is
end object ;

right object prod(A,B) with pair is
    pi1: prod -> A
    pi2: prod -> B
end object ;

left object coprod(A,B) with case is
    in1: A -> coprod
    in2: B -> coprod
end object ;

right object exp(A,B) with cur is
    ev: prod(exp, A) -> B
end object ;

left object bool with if is
    true  : 1 -> bool
    false : 1 -> bool
end object ;

left object nat with pr is
    o: 1 -> nat
    s: nat -> nat
end object ;

left object list(A) with fold is
    nil: 1 -> list
    cons : prod(A, list) -> list
end object ;

right object inflist(A) with unfold is
    get  : inflist -> A
    next : inflist -> inflist
end object ;
```

## 参考

-   [CPL (圏論プログラミング言語) - Wikipedia](http://ja.wikipedia.org/wiki/CPL_(%E5%9C%8F%E8%AB%96%E3%83%97%E3%83%AD%E3%82%B0%E3%83%A9%E3%83%9F%E3%83%B3%E3%82%B0%E8%A8%80%E8%AA%9E))
-   [カテゴリー理論的関数型プログラミング言語 (萩野 達也)](http://ci.nii.ac.jp/naid/110003743564)
-   [灘校パソコン研究部 / 圏論によるプログラミングと論理](http://www.npca.jp/2013/)
-   [圏論プログラミング言語 CPL - M59のブログ](http://mandel59.hateblo.jp/entry/2015/02/02/110621)
-   [CPL \| Hackage](http://hackage.haskell.org/package/CPL)

---

# 圏論プログラミング言語CPL入門

-   Wed Jun 10 22:47:14 JST 2015
    -   vimのpluginについての記述を追加
-   Thu Jun 25 22:47:45 JST 2015
    -   原始帰納法について注釈追加

---

# 圏論プログラミング言語CPL入門

[^1]: prはcatamorphismなので原始帰納法(paramorphism)と言ってしまうのは厳密でないかもしれない

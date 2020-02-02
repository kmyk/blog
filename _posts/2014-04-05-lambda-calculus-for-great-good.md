---
category: blog
layout: post
title: "すごいラムダ計算楽しく学ぼう"
date: 2014-04-05T20:24:26+09:00
tags: [ "lambda", "calculus", "function", "ski", "combinator" ]
---

-   以前挑んだ時は惨敗したが、今回は程よく分かるので楽しい
-   haskellにとってのlambda計算は、cにとってのbrainf\*ckみたいなものっぽい
-   教養の域を出なさそうだが楽しいので許す
-   楽しい(自己暗示)

<!-- more -->
<!-- c は色付けのため -->

## lambda計算とは
-   無名関数のみで計算
-   `λ x y. y x`
    -   haskellだと`\ x y -> y x`
    -   schemeだと`(lambda (x) (lambda (y) (y x)))`
    -   pythonだと`lambda x : lambda y : y(x)`
-   \# `λ`って打つの面倒なので`\`で代替


## 変換
alpha変換
:   変数の名前は変えれるよ `(\ a -> a) -> (\ b -> b)`
beta簡約
:   関数適用のこと `(\ x -> f x) y -> f y`
eta変換
:   const除去 `(\ _. a) b = (const a) b -> a`


## 関数
-   可読性のためhaskellから輸入しておく
-   combinator理論

``` c
const x y = x
id x = x
```

## church数
```
0 = \ s o.      o
1 = \ s o.    s o
2 = \ s o. s (s o)
succ n   = \ s o.   s (n s o)
plus m n = \ s o. m s (n s o)
mult m n = \ s. m (n s)
```

-   `(x -> x) -> x -> x`な関数を数とみなす
-   `numberToInt a = a (+1) 0 :: (forall x. (x -> x) -> x -> x) -> Int`
-   `Int -> (a -> a) -> a`な関数はhayooでググったら`nest`って名前ついてたけど、`3 ~ nest 3`と思えば自然

演算の定義別version

``` c
plus m n = m succ n
mult m n = m (plus n) 0
```

### pred
-   `- 1`
-   <-> `succ`
-   最大の山場だった
-   山場過ぎて[別記事](/blog/2014/04/05/church-number-and-pred-function/)に切り出した

### 減算
```
sub m n = n pred m
```

-   `plus m n = m succ n`なことを考えると当然だった
-   引数と定義部の順序の違いには注意すべきか


## 真偽値
```
true  t f = t
false t f = f
if p t f = p t f
```

``` c
if true  t f = t
if false t f = f
```

-   `a -> a -> a`を真偽値とみなす
-   分岐構造,jump命令が値に組み込まれている
-   `if`は構文糖

### 論理演算
```
not p   = \ t f. p f t
and p q = \ t f. p (q t f) f
or  p q = \ t f. p t (q t f)
xor p q = \ t f. p (q f t) (q t f)
```

-   所詮if文なので楽勝

``` c
not p   = p false true
and p q = p q false
or  p q = p true q
xor p q = p (not q) q
```

-   point-freeの綺麗な定義


## 比較

### 0判定
```
iszero n = n (const false) true
```

``` c
iszero 2
\ t f. iszero 2 t f
\ t f. 2 (const false) true t f
\ t f. (const false) ((const false) true) t f
\ t f. false t f
\ t f. f
false
```

``` c
iszero 0
\ t f. iszero 0 t f
\ t f. 0 (cons false) true t f
\ t f. true t f
\ t f. t
true
```

よく見たら定義からして`0 = flip const = false`だった

### 大小比較
```
gte m n = iszero (sub m n)
```

-   sub,predは負数にはならず0となるので

### 等値判定
```
equal m n = and (gte m n) (gte n m)
```

-   十分高級なので問題ないね


## loop
```
Y = \ f. (\ x. f (x x)) (\ x. f (x x)))
```

-   Y-combinatorと言うらしい
-   意外に簡単だった
-   というか既に慣れ親しんでた

``` c
Y f x
(\y.f(y y)) (\y.f(y y)) x
f ((\y.f(y y)) (\y.f(y y))) x
f (f ((\y.f(y y)) (\y.f(y y)))) x
```

やたら同じものが出てくるので`y = (\ x. f (x x))`とおいてみる

``` c
Y f x
y y x
f (y y) x
f (f (y y)) x
```

`Y`を`Y`で定義できそうなので元の式を弄くる

``` c
Y f = y y
    = f (y y)
    = f (Y f)
```

-   haskellのfixと全く同じだったようだ

### 階乗
lambda計算のような何か

``` c
fact = Y (\ recur n. (iszero n) 1 (mult n (recur (pred n))))
```

有効なhaskell-code

``` c haskell
fact = fix $ \ recur n -> if n == 0 then 1 else n * recur (n - 1)
```

完全に一致


## pair
```
pair l r = \ f. f l r
fst p = p (\ l r. l)
snd p = p (\ l r. r)
```

``` c
swap p = p (\ l r. r l)
uncurry f = \ p. p (\ l r. f l r)
uncurry f p = p f
```

問題ない


## list
```
cons x y = \ c n. c x (y c n)
nil      = \ c n. n
```

``` c
foldr f a0 xs
    = xs f a0
    = cons a (cons b (cons c (... (cons y (cons z nil))))) f a0
    = f    a (f    b (f    c (... (f    y (f    z  a0))))) f a0
```

``` c
map f = foldr (\ x. cons (f x)) nil
length = foldr (const succ) 0
```

-   church encoding と scott encoding の違いだとかはよく分からない
-   手計算なのでそろそろ不安
-   to be continued...


## 参考
主に [uid0130-blog: ラムダ計算の使い方](http://uid0130.blogspot.jp/2013/05/x.html)

他にも:

-   [ラムダ計算 - Wikipedia](http://ja.wikipedia.org/wiki/%E3%83%A9%E3%83%A0%E3%83%80%E8%A8%88%E7%AE%97)
-   [F#の基礎(嘘)](http://www.slideshare.net/bleistift/f-28987517)

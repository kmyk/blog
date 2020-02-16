---
category: blog
layout: post
date: 2014-04-05T21:04:13+09:00
tags: [ "church", "number", "lambda", "calculus", "predecessor", "function" ]
---

# チャーチ数とpred関数

``` c
pred n = \ s o. n (\ f g. g (f s)) (\ x. o) (\ x. x)
```

-   church数を`- 1`する関数
-   基本的なはずなのに、他のと比べてやけに複雑

<!-- more -->
<!-- c は色付けのため -->

## とりあえず手動簡約

よく分からないので名前つけてみる

``` c
embed x = \ f g. g (f x)
const x y = x
id x = x
pred n = \ s o. n (embed s) (const o) id
```

なにこれ:

-   embed
    -   `:: a -> (a -> b) -> (b -> c) -> c`
    -   なにこれ (後の繋がり的にembedと命名)
-   embed s
    -   なにこれ
-   const o
    -   なにこれ

気にせず簡約

``` c
pred 2
\ s o. pred 2 s o
\ s o. 2 (embed s) (const o) id
\ s o. (embed s) ((embed s) (const o)) id
\ s o. id (((embed s) (const o)) s)
\ s o. (embed s) (const o) s
\ s o. s ((const o) s)
\ s o. s o
1
```

何故か動く

``` c
pred 0
\ s o. pred 0 s o
\ s o. 0 (embed s) (const o) id
\ s o. (const o) id
\ s o. o
0
```

`-1`にはならないっぽい

## 簡約を追うのは諦めて、原理を考える

-   数は関数なので、分解やパターンマッチはできない
-   適用ならできる
-   1だけ減らしたい

<!-- -->

1.  よって、`\ s o. s (s (s (... (s (s o)))))`の`o`を活用するのは必然
2.  しかし、`o`は`s`に適用される側
3.  そこで、何かしらひっくり返す

つまり、`sss...sso`ではだめなので:

1.  `oss...sss`
2.  `sss...sos`

この`pred`の定義は後者のもよう (前者でもいけるのか否かは不明)

定義を再確認

``` c
embed x  f g
    = g (f x)
pred n = \ s o. n (embed s) (const o) id
```

その辺を意識してもう1度簡約  
`s`がどう並び替わるのか見るため番号振ります

``` c
pred 4
\ s o. pred 4 s o
\ s o. 4 (embed s) (const o) id
\ s o. (embed  s) ((embed  s) ((embed  s) ((embed  s) (const o)))) id
\ s o. (embed s1) ((embed s2) ((embed s3) ((embed s4) (const o)))) id
\ s o.        id ( (embed s2) ((embed s3) ((embed s4) (const o)))  s1)
\ s o.        id (        s1 ( (embed s3) ((embed s4) (const o))   s2))
\ s o.        id (        s1 (        s2 ( (embed s4) (const o)    s3)))
\ s o.        id (        s1 (        s2 (        s3 ((const o)    s4))))
\ s o.        id (        s1 (        s2 (        s3 (       o       ))))
\ s o. s (s (s o))
3
```

今回は`s4`(最も深い所の`s`)が`const`によって消えていますね


## 別な定義 on wikipedia
```
pred = \ n. n (\ g k. (g 1) (\ u. plus (g k) 1) k) (\ v. 0) 0
```

>   上の部分式 (g 1) (\ u. PLUS (g k) 1) k は、 g(1) がゼロとなるとき k に評価され、そうでないときは g(k) + 1 に評価されることに注意せよ。

-   もう1つあったので追ってみる
-   注意書きが要るぐらいには複雑らしい

``` c
f g k = g 1 (const (plus (g k) 1)) k
pred n = n f (const 0) 0
```

### 誘導に従う

(g 1)が0になるとき

``` c
g = const 0
f (const 0) k
    = const 0 1 (const (plus (const 0 k) 1)) k
    = 0 (const (plus (const 0 k) 1)) k
    = (\ s o. o) (const (plus (const 0 k) 1)) k
    = k
f (const 0) = id
```

そうでない(0でない数である)とき

``` c
g :: number -> number
(g 1) != 0
f g k
    = (g 1) (const (plus (g k) 1)) k
    = (const (plus (g k) 1)) ((const (plus (g k) 1)) (... ((const (plus (g k) 1)) k)))
    =        (plus (g k) 1)
    = succ (g k)
f   id k =       succ k
f succ k = succ (succ k)
```

まとめると

``` c
pred n
    = n f (const 0) 0
    = f (f (f (... (f (f (f (const 0)) ))))) 0
    = f (f (f (... (f (f id            ))))) 0
    = f (f (f (... (f (\ n. succ (id n)))))) 0
    = f (f (f (... (f (\ n. succ n     ))))) 0
    = f (f (f (... (\ n. succ (succ n)  )))) 0
    = (\n. succ (succ (succ (... (succ (succ n)))))) 0
    =      succ (succ (succ (... (succ (succ 0)))))
```

だいたい先ほどのと同じですね

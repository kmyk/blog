---
category: blog
layout: post
title: "一点基底について調べた"
date: 2014-04-13T13:53:18+09:00
tags: [ "one-point-basis", "ski", "combinator" ]
---

| 発見者              | 一点基底          | `S`                                   | `K`                           | 他
|---------------------+-------------------+---------------------------------------+-------------------------------+-----------------------------
|                     | `\x.xSK`          | `X(X(X(XX)))`                         | `X(X(XX))`                    | `I = XX`, iotaで使われている
| John Barkley Rosser | `\x.xKSK`         | `X(XX)`                               | `XXX`                         |
| Corrado Bohm        | `\x.x(fS(KI))K`   | `X(XX)`                               | `XX`                          |
| Henk Barendregt     | `\x.x(fS(KK))K`   | `X(XXX)`                              | `XXX`                         |
| Jeroen Fokker       | `\f.fS(\xyz.x)`   | `X(XX)`                               | `XX`                          |
| Carew Meredith      | `\abcd.cd(a(Kd))` | `V(XXX(XX)(XXXX(XXXX(VV))(K(XXXX))))` | `XXXX(XXXX(XXX(XX))(XX))(XX)` | `V = XXXX(K(XXXX))`とする

<!-- more -->

## let's 簡約
iotaのものを簡約する

``` scheme
# XX = I
XX a
    = (\x.xSK) (\y.ySK) a
    = ((\y.ySK) SK) a
    = ((S SK) K) a
    = ((SK) (KK)) a
    = SK (KK) a
    = (Ka) (KKa)
    = a
    = I a
```

``` scheme
# X(X(XX)) = K
X(X(XX))
    = X(XI)
    = (\x.xSK) ((\y.ySK) I)
    = (\x.xSK) (I SK)
    = (\x.xSK) (SK)
    = (SK SK)
    = ((KK) (SK))
    = K
```

``` scheme
# X(X(X(XX))) = S
X(X(X(XX)))
    = XK
    = (\x.xSK) K
    = KSK
    = S
```

## 参考

-   [&amp;lambda;x. x K S K - λx.x K S K ＠ はてな](http://d.hatena.ne.jp/KeisukeNakano/20061008/1160288593)
    -   冒頭の表はほぼこの記事をまとめただけ
-   [コンビネータ論理 # One-point basis- Wikipedia](http://ja.wikipedia.org/wiki/%E3%82%B3%E3%83%B3%E3%83%93%E3%83%8D%E3%83%BC%E3%82%BF%E8%AB%96%E7%90%86#One-point_basis)
-   [Iota and Jot - Wikipedia, the free encyclopedia](https://en.wikipedia.org/wiki/Iota_and_Jot)

---
category: blog
layout: post
title: "template haskellでfoldを定義させてみた"
date: 2014-08-30T09:41:12+09:00
tags: [ "template", "haskell", "fold" ]
---

``` haskell
data Tree a = Leaf a | Tree (Tree a) (Tree a) deriving (Show)
$(catamorphism ''Tree "foldTree")
```

と呼び出すと

``` haskell
>>> :t foldTree
foldTree :: (a0 -> a1) -> (a1 -> a1 -> a1) -> Tree a0 -> a1
>>> foldTree id (++) (Tree (Leaf "foo") (Tree (Leaf "bar") (Leaf "baz")))
"foobarbaz"
```

と定義される

楽しい

<!-- more -->

## 中身

[Catamorphism.hs](https://github.com/kmyk/etude/blob/master/haskell/Catamorphism.hs)

``` haskell
a.hs:1:1: Splicing declarations
    catamorphism ''Tree "foldTree"
  ======>
    a.hs:8:1-30
    foldTree ::
      forall a_a25h a_a2ml.
      (a_a25h -> a_a2ml)
      -> (a_a2ml -> a_a2ml -> a_a2ml) -> Tree a_a25h -> a_a2ml
    foldTree f_a2mm f_a2mn x_a2mq
      = g_a2mr x_a2mq
      where
          g_a2mr (Leaf y_a2mo) = f_a2mm y_a2mo
          g_a2mr (Tree y_a2mo y_a2mp)
            = f_a2mn (g_a2mr y_a2mo) (g_a2mr y_a2mp)
```

-   やるだけ
-   100行ぐらい
-   多相型は少し面倒

## 参考

-   [できる！Template Haskell (完) - はてな使ったら負けだと思っている deriving Haskell](http://haskell.g.hatena.ne.jp/mr_konn/20111218/1324220725)
-   [Hackage: thorn](http://hackage.haskell.org/package/thorn)
-   [Hackage: th-fold](http://hackage.haskell.org/package/th-fold)

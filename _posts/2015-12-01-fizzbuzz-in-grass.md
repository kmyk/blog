---
category: blog
layout: post
title: "Grassでfizzbuzzを書いた"
date: 2015-12-01T00:00:01+09:00
tags: [ "grass", "esolang", "fizzbuzz", "haskell", "dsl", "monad", "lambda-calculus" ]
---

多めに植えておきました。

7666 byte

```
wvwwWWWwwvwwwWWWwwWwwWWWWwvwwwwWWWWwwWWWWwwwWwwwWWWwvwwwwWWWwwWWWWWwWwwwvwwWWWWW
WWwvwwWWwvwwWWwWWWwvwWWWWWwwWwwwWwwwvwWWWWWWwwwWwwwWwwwvwWWWWWWWwwwwWwwwWwwwvwWW
WWWWWWwwwwwWwwwWwwwvwWWWWWWWWWwwwwwwWwwwWwwwvwWWWWWWWWWWwwwwwwwWwwwWwwwvwwWWWWWW
WWWWWWWWWWwwvwwWWWWWWWWWWWWWWWWWwvwwwWwwwWwwwvwWwwwWWWwWWWwwwwwWWWWWWWWWWWWWWWWW
WWwWWWwvwWwwWWWWwwwwwwwwwwwwwwwWwwwwwwwwwwwwwwwwWWWwWwwwwwwwwwvwwWwwwWwwwvwwWWwW
wwwwwwwwvwwWWwwwwwwwwwWwwvwWwwwwwwwwWwwwwwwwwwwvwWWWWWWWWWWWWWWWWWWWWWWWwwwwwwww
wWWwWwwwwwwwwwwwwvwwWWWWWWWwwWwwWWWWWwvwwWWWwwWwwWWWWWWWWWwWWWWWWwwwwWwwwwwwWWWw
vwwWWWWWWWWWWWWWWWWWWWWWWWWWWwWWWWwwwWwwWwwwwwwwwwwwwwwwwwwwwwwwwwwWwwwwvwwwwwWw
wwwwWwwwwwWwwwwwWwwwwwvwwwwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwwwwvwWwwvwwwwWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWwwwvwWwwvwwwwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwwvw
WwwvwwwwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwvwWwwvwWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww
wwwwwwwwwwwwwwwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww
wwwwwwwwwwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwWwwwwwwwwwwwwwwwwwww
wwwwwwwwwwwwwwwwwwwwwwwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwWwwww
wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWwwwwwwwwwwwwwwwwwwwww
wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww
wwwwwwwwwwwwwwwwwwwwwwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwwwwwwwwwwwwwwwwww
wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww
wwwwwwwwwwwwwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwW
wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwvwWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwww
wwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWwwwwwwwwwwwwwwwwwww
wwwwwwwwwwwwwwwwwwwwwwwwwwwwwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWwwwwwwwwwwwwwwwwwwwww
wwwwwwwwwwwwwwwwwwwwwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwWwwwwwwwww
wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww
wwwwwwwwwwwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwWwwwwwwwwwww
wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww
wwwwwwwwwwwwwwwwwwwwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww
wwwwwwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwwwwwwwwwwwwwwwwwwwwwwwwwwww
wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww
wwwwwwwwwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWw
wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwvwWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWwwwwwwwwwwwwwww
wwwwwwwwwwwwwwwwwwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwWwwwwwwwwwwwwwwwwwwwwww
wwwwwwwwwwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwWwwwwwwwwwwwwwwwwwwwwwwwwwwww
wwwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWwwwwwwwwwwwwwwwwwwwwwwwwwwww
wwwwwwwwwwwwwwwwwwwwwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwwwwwwwwwwvwWwwwwwwwwwwwwwwwwwwwwwwwwwwwww
wwwwwwwwwwwwwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwwwwwwwwwwwwwwwwwwwwwwwwwwwww
wwwwwwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
wWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwW
wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWw
WwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww
wwwwwwwwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWWWWWWWWWWWwvWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwvWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwvWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwvWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWwvwWWWWWWWWWWWWWWWWwWWWWWWWWWWWWWWWwwWWWWWWWWWWWWWWwwwWWWWWWWWWWW
WWwwwwWWWWWWWWWWWWWWWWWWWWWWWWWWwwWWWWWWWWWWWWWWWWWWWWWWWWWWWwwWWwwwwwwwwwwwwwww
WwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWwWWWWwwwwwwwwwwwwwwwwwWwww
wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWwWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWwwwwwwwwWwwwwwwwwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwwwwwwwwwwwwwwww
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwWWWwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww
wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww
wwwwwwwwwwwwwwwwwWWWWWWWWWWWWWWWWWWWWWWWWWWWwwwwwwwwwwwwwwwwwwwwwWWwWWWWWWWWWwww
wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWwwwwwwwwwwwww
wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWwwwwwwwwwwwwwwwwwwwwwwwwWWwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWwwwwwwwwwwwww
wwwwwwwwwwwwwwwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwWwwwwwwwwwww
wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWwwwwwwwwwwwwwwww
wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWwwwwwwwwwwwwwwwwww
wwwwwwwwwwwwwwwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwwwwwwwwwwww
wwwwwwwwwwwwwwwwwwwwwwwwwwwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWwww
wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWwwwwwWwwwwwwwwwwWwwwwwWwwwwvwWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWw
wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWw
wwwwwWWWWWWWWWWWWWWWWWWWWWWWWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWwwww
wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww
wwwwwwwwwwWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWWWWWwv
```

<!-- more -->

今回はrichなdslを作った。単にmonadの力で殴っただけであるが、grassのgrassとしての面白さを覆い隠すには十分強力である。
もはや普通のlambda計算であるので、ただ書くだけである。

やはりesolang遊びにはhaskellは必須である。
関数適用の演算子が面倒であるが、これを解決するとするとlispで構造のparseから始めることになるので、許容されるべきものである。

ところでanarchy golfにfizzbuzzを[提出](http://golf.shinh.org/p.rb?FizzBuzz#Grass)しているのは私以外いない。プロたちはhelloworldを詰めて満足してしまったのだろうか。

``` haskell
module Main where
import Control.Exception
import Control.Monad
import Data.Bits
import Data.Char
import Data.Word

data Grass context a = Grass (Int -> (a, String, Int))
newtype Lambda = Lambda Int deriving (Eq, Ord, Show, Read)
data TopLevel
data Body

instance Functor (Grass context) where
    fmap f (Grass g) = Grass $ \ i ->
        let (a, s, j) = g i
            in (f a, s, j)
instance Applicative (Grass context) where
    pure a = Grass $ \ i -> (a, "", i)
    Grass f <*> Grass g = Grass $ \ i ->
        let (h, s, j) = f i
            (a, t, k) = g j
            in (h a, s ++ t, k)
instance Monad (Grass context) where
    Grass f >>= g' = Grass $ \ i ->
        let (a, s, j) = f i
            Grass g = g' a
            (b, t, k) = g j
            in (b, s ++ t, k)

define :: Int -> ([Lambda] -> Grass Body a) -> Grass TopLevel Lambda
define n f' =
    assert (n > 0) $
    Grass $ \ i ->
        let args = map Lambda [i..i+n-1]
            Grass f = f' args
            (_, s, _) = f (i+n)
            in (Lambda i, replicate n 'w' ++ s ++ "v", i+1)
apply :: Lambda -> Lambda -> Grass Body Lambda
apply (Lambda f) (Lambda x) = Grass $ \ i ->
    (Lambda i, replicate (i-f) 'W' ++ replicate (i-x) 'w', i+1)

runGrass :: Grass TopLevel a -> String
runGrass (Grass f) = let (_, s, _) = f l in s where
    l = length [gOut, gSucc, gW, gIn]

application :: Lambda -> Lambda -> Grass TopLevel Lambda
application f x = Grass $ \ i ->
    let Grass g = apply f x
        (a, s, j) = g i
        in (a, s ++ "v", j)

gIn :: Lambda
gIn = Lambda 0
gW :: Lambda
gW = Lambda 1
gSucc :: Lambda
gSucc = Lambda 2
gOut :: Lambda
gOut = Lambda 3

mDummy :: Grass context Lambda
mDummy = Grass $ \ i -> (Lambda (i - 1), "", i)

(<\\>) :: Lambda -> Lambda -> Grass Body Lambda
f <\\> g = apply f g
(</\>) :: Grass Body Lambda -> Lambda -> Grass Body Lambda
f </\> g = join $ liftM2 apply f (pure g)
(<//>) :: Grass Body Lambda -> Grass Body Lambda -> Grass Body Lambda
f <//> g = join $ liftM2 apply f g
(<\/>) :: Lambda -> Grass Body Lambda -> Grass Body Lambda
f <\/> g = join $ liftM2 apply (pure f) g
infixl 4 <\\>, </\>, <//>

main :: IO ()
main = putStrLn . runGrass $ do
    gI <- define 1 $ \ [_] -> return ()
    let ret a = gI <\\> a
    gK <- define 2 $ \ [x, _] -> ret x
    gSuccN <- define 3 $ \ [n, f, x] -> f <\/> (n <\\> f </\> x)
    gPlus <- define 4 $ \ [m, n, f, x] -> m <\\> f <//> (n <\\> f </\> x)
    gMult <- define 4 $ \ [m, n, f, x] -> m <\/> (n <\\> f) </\> x
    g0   <- define 2 $ \ [_, x] -> ret x
    g1   <- define 2 $ \ [f, x] -> f <\\> x
    g2   <- define 2 $ \ [f, x] -> f <\/> (f <\\> x)
    g4   <- define 1 $ \ [f] -> gMult <\\> g2 </\> g2  </\> f
    g8   <- define 1 $ \ [f] -> gMult <\\> g2 </\> g4  </\> f
    g16  <- define 1 $ \ [f] -> gMult <\\> g2 </\> g8  </\> f
    g32  <- define 1 $ \ [f] -> gMult <\\> g2 </\> g16 </\> f
    g64  <- define 1 $ \ [f] -> gMult <\\> g2 </\> g32 </\> f
    g128 <- define 1 $ \ [f] -> gMult <\\> g2 </\> g64 </\> f
    let mSum :: [Lambda] -> Grass Body Lambda
        mSum (x : xs) = foldl (\ a b -> gPlus <\/> a </\> b) (pure x) xs
        mSum [] = return g0
    let mN :: Word8 -> Grass Body Lambda
        mN n = mSum . map fst . filter snd . zip [g1, g2, g4, g8, g16, g32, g64, g128] $ map (testBit n) [0..7]
    let mC :: Char -> Grass Body Lambda
        mC c = mN (fromIntegral $ (ord c - ord 'w') `mod` 256) </\> gSucc </\> gW
    gTrue  <- define 2 $ \ [t, _] -> ret t
    gFalse <- define 2 $ \ [_, f] -> ret f
    gPair <- define 3 $ \ [a, b, p] -> p <\\> a </\> b
    let mFst p = p <\\> gTrue
    let mSnd p = p <\\> gFalse
    gPredN <- do
        helper <- define 1 $ \ [p] -> gPair <\/> mSnd p <//> (gSuccN <\/> mSnd p)
        define 1 $ \ [n] -> mFst =<< (n <\\> helper <//> (gPair <\\> g0 </\> g0))
    gMinus <- define 2 $ \ [n, m] -> m <\\> gPredN </\> n
    gAnd <- define 2 $ \ [p, q] -> p <\\> q </\> gFalse
    gOr  <- define 2 $ \ [p, q] -> p <\\> gTrue </\> q
    gNot <- define 1 $ \ [p] -> p <\\> gFalse </\> gTrue
    gIsZero <- define 1 $ \ [n] -> n <\/> (gK <\\> gFalse) </\> gTrue
    gLe <- define 2 $ \ [m, n] -> gIsZero <\/> (gMinus <\\> m </\> n)
    gEq <- define 2 $ \ [m, n] -> gAnd <\/> (gLe <\\> m </\> n) <//> (gLe <\\> n </\> m)
    gSuccMod <- define 2 $ \ [p, n] -> do
        n' <- gSuccN <\\> n
        (gEq <\\> p </\> n') </\> g0 </\> n'
    gPair4 <- define 5 $ \ [a, b, c, d, p] -> p <\\> a </\> b </\> c </\> d
    gPi41 <- do
        helper <- define 4 $ \ [a, _, _, _] -> ret a
        define 1 $ \ [p] -> p <\\> helper
    gPi42 <- do
        helper <- define 4 $ \ [_, b, _, _] -> ret b
        define 1 $ \ [p] -> p <\\> helper
    gPi43 <- do
        helper <- define 4 $ \ [_, _, c, _] -> ret c
        define 1 $ \ [p] -> p <\\> helper
    gPi44 <- do
        helper <- define 4 $ \ [_, _, _, d] -> ret d
        define 1 $ \ [p] -> p <\\> helper
    gFizz <- define 1 $ \ [a] -> do
        void $ gOut <\/> mC 'F'
        void $ gOut <\/> mC 'i'
        void $ gOut <\/> (gOut <\/> mC 'z')
        ret a
    gBuzz <- define 1 $ \ [a] -> do
        void $ gOut <\/> mC 'B'
        void $ gOut <\/> mC 'u'
        void $ gOut <\/> (gOut <\/> mC 'z')
        ret a
    gNewline <- define 1 $ \ [a] -> do
        void $ gOut <\/> mC '\n'
        ret a
    gDigit <- define 1 $ \ [n] -> n <\\> gSucc <//> mC '0'
    g3  <- application gSuccN g2
    g5  <- application gSuccN g4
    g9  <- application gSuccN g8
    g10 <- application gSuccN g9
    gFizzBuzz <- define 1 $ \ [p] -> do
        a <- gPi41 <\\> p  -- n / 10
        b <- gPi42 <\\> p  -- n % 10
        c <- gPi43 <\\> p  -- n % 3
        d <- gPi44 <\\> p  -- n % 5
        isFizz <- gIsZero <\\> c
        isBuzz <- gIsZero <\\> d
        void $ (isFizz <\\> gFizz </\> gI) <//> mDummy
        void $ (isBuzz <\\> gBuzz </\> gI) <//> mDummy
        isNum <- gNot <\/> (gOr <\\> isFizz </\> isBuzz)
        void $ ((gAnd <\\> isNum <//> (gNot <\/> (gIsZero <\\> a))) </\> gOut </\> gI) <//> (gDigit <\\> a)
        void $ (isNum <\\> gOut </\> gI) <//> (gDigit <\\> b)
        void $ gNewline <\/> mDummy
        b' <- gSuccMod <\\> g10 </\> b
        a' <- ((gIsZero <\\> b') </\> gSuccN </\> gI) </\> a
        c' <- gSuccMod <\\> g3  </\> c
        d' <- gSuccMod <\\> g5  </\> d
        gPair4 <\\> a' </\> b' </\> c' </\> d'
    define 1 $ \ [_] ->
        mN 100 </\> gFizzBuzz <//> (gPair4 <\\> g0 </\> g1 </\> g1 </\> g1)
```


---

この記事は[KobeUniv Advent Calendar 2015](http://www.adventar.org/calendars/891)の1日目の記事として書かれました。
前々からgrassはやりたいなと思ってはいたが、特に書く機会もなかったのでちょうどよかったように思います。

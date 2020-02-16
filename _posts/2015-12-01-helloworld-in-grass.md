---
category: blog
layout: post
date: 2015-12-01T00:00:00+09:00
tags: [ "esolang", "grass", "helloworld", "haskell", "dsl", "lambda-calculus", "golf" ]
---

# Grassでhelloworldを書いた

植えました。

1951 byte

```
wwwwWWWWwwWWWWwwwWwwwWWWwvwwwwWWWwwWWWWWwWwwwvwwWWwWWWwvwWWWwwWwwwWwwwvwWWWWwwwW
wwwWwwwvwWWWWWwwwwWwwwWwwwvwWWWWWWwwwwwWwwwWwwwvwWWWWWWWwwwwwwWwwwWwwwvwWWWWWWWW
wwwwwwwWwwwWwwwvwWWWWWWWWWWWWwvwWWWwwWwwwwwwwwwwwwwwwWWWWWWwwwwWwwWWWWWWWWWWwwww
wwWwwWWWWWWWWwWWWWWWWWwvwWWWWwwwWwwwwwwwwwwwwwwwwWWWWWWWwwwwwWwwWWWWWWWWWWwwwwww
wWwwWWWWWWWWWWWWWWwwwwwwwwwWwwWWWWWWWWWWWWWWWWWwwwwwwwwwwwWwwWWWWWWWWWWWWWWWWWWW
WwwwwwwwwwwwwwWwwWWWWWWWWWWWWWwvwWWWWWwwwwWwwwwwwwwwwwwwwwwwWWWWWWWWwwwwwwWwwWWW
WWWWWWWWwwwwwwwwWwwWWWWWWWWWWWWWWwwwwwwwwwwWwwWWWWWWWWWWWWWWWWWWwwwwwwwwwwwwWwwW
WWWWWWWWWWWWWwWWWWWWWWWWWWwvwWWWWWWwwwwwWwwwwwwwwwwwwwwwwwwWWWWWWWWWwwwwwwwWwwWW
WWWWWWWWWWwwwwwwwwwWwwWWWWWWWWWWWWWWWwwwwwwwwwwwWwwWWWWWWWWWWWWWWWWWWwwwwwwwwwww
wwWwwWWWWWWWWWWWwvwWWWWWWWwwwwwwWwwwwwwwwwwwwwwwwwwwWWWWWWWWWWWwwwwwwwwWwwWWWWWW
WWWWWWWWwwwwwwwwwwWwwWWWWWWWWWWWWWWWWWWwwwwwwwwwwwwWwwWWWWWWWWWWWWWWwWWWWWWWWWWw
vwWWWWWWWWwwwwwwwWwwwwwwwwwwwwwwwwwwwwWWWWWWWWWWWWwwwwwwwwwWwwWWWWWWWWWWWWWWWWww
wwwwwwwwwWwwWWWWWWWWWWWWWwWWWWWWWWwvwWWWWWWWWWwwwwwwwwWwwwwwwwwwwwwwwwwwwwwwWWWW
WWWWWWWWwwwwwwwwwwWwwWWWWWWWWWWWWWWWwwwwwwwwwwwwWwwWWWWWWWWWWWWWWWWWWwwwwwwwwwww
wwwWwwWWWWWWWWWWWWWWWWWWWWWwwwwwwwwwwwwwwwwWwwWWWWWWWWWWWWWWWWWWWWWWWWWwwwwwwwww
wwwwwwwwwWwwWWWWWWWWWWWWWWWWWWWWwWWWWWWWWWWWWWWwvwWWWWWWWWWWwwwwwwwwwWwwwwwwwwww
wwwwwwwwwwwwWWWWWWWWWWWWWwwwwwwwwwwwWwwWWWWWWWWWWWWWWWWwwwwwwwwwwwwwWwwWWWWWWWWW
WWWWWWWWWWWwwwwwwwwwwwwwwwWwwWWWWWWWWWWWWWWWWWWWWWWWwwwwwwwwwwwwwwwwwWwwWWWWWWWW
WWWWWWWWWWWwWWWWWWWWWWWWwvwWWWWWWWWWWWwwwwwwwwwwWwwwwwwwwwwwwwwwwwwwwwwwWWWWWWWW
WWWWWWWwwwwwwwwwwwwWwwWWWWWWWWWWWWWWWWWWWwwwwwwwwwwwwwwWwwWWWWWWWWWWWWWWWWWWWWWW
WwwwwwwwwwwwwwwwwWwwWWWWWWWWWwvwWWWWWWWWWWWWWWWWWWWWWwvwWWWWWWWWWWWwwWWWWWWWWWWW
wwwWWWWWWWWWWWwwwwWWWWWWWWWWWWwwwwwWWWWWWWWWWWWwwwwwwWWWWWWWWWWWWwwwwwwwWWWWWWWW
WWWWwwwwwwwwWWWWWWWWWwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwWWWWWWWWWWWWWWWWwwwwwwwwwwWW
WWWWWWWWWWWWwwwwwwwwwwwWWWWWWWWWWWWWWWWWWWwwwwwwwwwwwwWWWWWWWWWWWWWWWwwwwwwwwwww
wwWWWWWWWWWWWWWWWwwwwwwwwwwwwww
```

<!-- more -->

もちろん直書きではないが、できるだけgrassの文法構造を尊重した。grassの構造と1対1に対応するdslから生成した。そのせいで結構手間がかかった。

またanarchy golfに[提出](http://golf.shinh.org/p.rb?hello+world#Grass)したところ、1位の人の5倍ほどの長さであった。
分かりやすさを優先し無駄の多い構造になっているので、500byte程度までであればそう苦労せず縮められるのではないかと見ている。

``` haskell
module Main where
import Data.List

data Grass = Grass [Abs] deriving (Eq, Ord, Show, Read)
data Abs = Abs Int [App] deriving (Eq, Ord, Show, Read)
data App = App Int  Int  deriving (Eq, Ord, Show, Read)

encode :: Grass -> String
encode (Grass abss) = intercalate "v" $ map f abss where
    f (Abs n apps) = replicate n 'w' ++ concatMap g apps
    g (App a b) = replicate a 'W' ++ replicate b 'w'

main :: IO ()
main = putStrLn . encode $ Grass
    [ Abs 4 -- +, \mnfx.mf(nfx)
        [ App 4 2
        , App 4 3
        , App 1 3
        , App 3 1
        ]
    , Abs 4 -- *, \mnfx.m(nf)x
        [ App 3 2
        , App 5 1
        , App 1 3
        ]
    , Abs 2 [ App 2 1 , App 3 1 ] -- 2
    , Abs 1 [ App 3 2 , App 1 3 , App 1 3 ] -- 4
    , Abs 1 [ App 4 3 , App 1 3 , App 1 3 ] -- 8
    , Abs 1 [ App 5 4 , App 1 3 , App 1 3 ] -- 16
    , Abs 1 [ App 6 5 , App 1 3 , App 1 3 ] -- 32
    , Abs 1 [ App 7 6 , App 1 3 , App 1 3 ] -- 64
    , Abs 1 [ App 8 7 , App 1 3 , App 1 3 ] -- 128
    , Abs 1 -- copy of succ
        [ App 12 1
        ]
    , Abs 1 -- H, 209 = 72 + 119 = 128 + 64 + 16 + 8 + 2 + 1, (\f. f 'H')
        [ App  3 2 , App 1 15
        , App  6 4 , App 1 2
        , App 10 6 , App 1 2
        , App    8  1
        , App  8 1
        ]
    , Abs 1 -- e, 238 = 128 + 64 + 32 + 8 + 4 + 2
        [ App  4  3 , App 1 16
        , App  7  5 , App 1 2
        , App 10  7 , App 1 2
        , App 14  9 , App 1 2
        , App 17 11 , App 1 2
        , App 20 13 , App 1 2
        , App 13  1
        ]
    , Abs 1 -- l, 245 = 128 + 64 + 32 + 16 + 4 + 1
        [ App  5  4 , App 1 17
        , App  8  6 , App 1 2
        , App 11  8 , App 1 2
        , App 14 10 , App 1 2
        , App 18 12 , App 1 2
        , App    14 1
        , App 12  1
        ]
    , Abs 1 -- o, 248 = 128 + 64 + 32 + 16 + 8
        [ App  6  5 , App 1 18
        , App  9  7 , App 1 2
        , App 12  9 , App 1 2
        , App 15 11 , App 1 2
        , App 18 13 , App 1 2
        , App 11  1
        ]
    , Abs 1 -- ,, 181 = 128 + 32 + 16 + 4 + 1
        [ App  7  6 , App 1 19
        , App 11  8 , App 1 2
        , App 14 10 , App 1 2
        , App 18 12 , App 1 2
        , App    14 1
        , App 10  1
        ]
    , Abs 1 --  , 169 = 128 + 32 + 8 + 1
        [ App  8  7 , App 1 20
        , App 12  9 , App 1 2
        , App 16 11 , App 1 2
        , App    13 1
        , App  8  1
        ]
    , Abs 1 -- r, 251 = 128 + 64 + 32 + 16 + 8 + 2 + 1
        [ App  9  8 , App 1 21
        , App 12 10 , App 1 2
        , App 15 12 , App 1 2
        , App 18 14 , App 1 2
        , App 21 16 , App 1 2
        , App 25 18 , App 1 2
        , App    20 1
        , App 14  1
        ]
    , Abs 1 -- d, 237 = 128 + 64 + 32 + 8 + 4 + 1
        [ App 10  9 , App 1 22
        , App 13 11 , App 1 2
        , App 16 13 , App 1 2
        , App 20 15 , App 1 2
        , App 23 17 , App 1 2
        , App    19 1
        , App 12  1
        ]
    , Abs 1 -- !, 170 = 128 + 32 + 8 + 2
        [ App 11 10 , App 1 23
        , App 15 12 , App 1 2
        , App 19 14 , App 1 2
        , App 23 16 , App 1 2
        , App  9  1
        ]
    , Abs 1 -- copy of out
        [ App 21 1
        ]
    , Abs 1
        [ App 11  2 -- H
        , App 11  3 -- e
        , App 11  4 -- l
        , App 12  5 -- l
        , App 12  6 -- o
        , App 12  7 -- ,
        , App 12  8 --
        , App     9 31 -- w
        , App 16 10 -- o
        , App 14 11 -- r
        , App 19 12 -- l
        , App 15 13 -- d
        , App 15 14 -- !
        ]
    ]
```

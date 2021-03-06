---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/303/
  - /blog/2016/06/29/yuki-303/
date: 2016-06-29T22:07:48+09:00
tags: [ "competitive", "writeup", "yukicoder", "matrix", "fibonacci" ]
"target_url": [ "http://yukicoder.me/problems/no/303" ]
---

# Yukicoder No.303 割れません

やるだけって言いながらDPを書いたらoverflowした。

## solution

fibonacci数。多倍長整数の行列を繰り返し二乗する。
$\newcommand{dp}{\mathrm{dp}}$
$\newcommand{fib}{\mathrm{fib}}$

単純なDPを考えると、

-   $\dp\_0 = 1$
-   $\dp\_{\frac{l}{2}} = 0$
-   $\dp\_{i} = \Sigma\_{j \lt i, j-i \operatorname{is odd}} \dp\_j$

である。

-   $\mathrm{acc}\_{0,i} = \Sigma\_{j \lt i, j \operatorname{is even}} \dp\_j$
-   $\mathrm{acc}\_{1,i} = \Sigma\_{j \lt i, j \operatorname{is odd}} \dp\_j$

とすると、最後の漸化式は

-   $\dp\_{2i} = \mathrm{acc}\_{1,2i}$
-   $\dp\_{2i+1} = \mathrm{acc}\_{0,2i+1}$

と書ける。

一旦$l$を無視して考えると、

-  $\dp_0 = 1$
-  $\dp_i = \fib\_i$

である。ただし

-  $\fib\_0 = 1$
-  $\fib\_1 = 1$

とする。
これは、

-   $\dp\_{2i+2} = \mathrm{acc}\_{1,2i+2} = \mathrm{acc}\_{1,2i} + \dp\_{2i+1} = \dp\_{2i} + \dp\_{2i+1}$
-   $\dp\_{2i+3} = \mathrm{acc}\_{0,2i+3} = \mathrm{acc}\_{0,2i+1} + \dp\_{2i+2} = \dp\_{2i+1} + \dp\_{2i+2}$

となることから分かる。
よって、$l$が奇数の場合は

-   $\mathrm{ans}(l) = \fib_l$

でよい。

次に、$l$が偶数の場合について。
$\frac{l}{2}$が使えないことを考慮に入れると、$l = 2h$として、

-   $\dp\_{i} = \fib\_i$ if $i \lt h$
-   $\dp\_{h} = 0$
-   $\dp\_{h+1} = \mathrm{acc}\_{h-1} + \dp\_{h} = \mathrm{acc}\_{h-1} = \dp\_{h-1} = \fib\_{h-1}$
-   $\dp\_{h+2} = \mathrm{acc}\_{h} + \dp\_{h+1} = \dp\_{h-2} + \dp\_{h-1} + \dp\_{h+1} = \fib\_{h+1}$
-   $\dp\_{h+i} = \dp\_{h+i-2} + \dp\_{h+i-1}$ if $i \gt 2$

である。$h+2$も例外となっている。

-   $a = \dp\_{h-1} = \fib\_{h-1}$
-   $b = \dp\_{h-2} - \dp\_{h-1} = \fib\_{h+1} - \fib\_{h-1} = \fib_h$

として、

-   $\dp\_{h+i} = a \fib\_{i} + b \fib\_{i-1}$ if $i \gt 2$

と書ける。
よって、

-   $\mathrm{ans}(2h) = \dp\_{h+h} = a \fib\_{h} + b \fib\_{h-1} = 2\fib\_{h-1}\fib\_{h}$

となる。

## implementation

c++での多倍長整数演算は以前書いてるが、引っぱり出してくるのが面倒だった。

``` haskell
module Main where
import Data.Bits
import Data.Monoid

data Mat22 a = Mat22 a a a a deriving (Eq, Ord, Show, Read)

instance Num a => Monoid (Mat22 a) where
    mempty = Mat22 1 0 0 1
    mappend (Mat22 a00 a01 a10 a11) (Mat22 b00 b01 b10 b11)
        = Mat22 (a00 * b00 + a01 * b10) (a00 * b01 + a01 * b11) (a10 * b00 + a11 * b10) (a10 * b01 + a11 * b11)

fib :: Int -> Integer
fib n = unpack $ go f0 mempty 1 where
    f0 = Mat22 1 1 1 0
    go :: Mat22 Integer -> Mat22 Integer -> Int -> Mat22 Integer
    go _ g i | i > n = g
    go f g i = if n .&. i == 0
        then go (f <> f)       g  (i `shift` 1)
        else go (f <> f) (f <> g) (i `shift` 1)
    unpack (Mat22 a b c d) = b

solve :: Int -> Integer
solve l = if l `mod` 2 == 0
    then let h = l `div` 2 in 2 * fib (h-1) * fib h
    else fib l

main :: IO ()
main = do
    l <- readLn
    let y = solve l
    if y == 0
        then do
            print $ l+1
            putStrLn "INF"
        else do
            print l
            print y
```

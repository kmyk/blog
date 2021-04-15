---
layout: post
redirect_from:
  - /writeup/algo/hackerrank/lambda-calculi-march-2016-lambda-march-compute-the-perimeter-of-a-polygon/
  - /blog/2016/03/28/hackerrank-lambda-calculi-march-2016-lambda-march-compute-the-perimeter-of-a-polygon/
date: 2016-03-28T15:26:14+09:00
tags: [ "competitive", "writeup", "hackerrank", "lambda-calculi", "haskell" ]
"target_url": [ "https://www.hackerrank.com/contests/lambda-calculi-march-2016/challenges/lambda-march-compute-the-perimeter-of-a-polygon" ]
---

# Lambda Calculi - March 2016: Compute the Perimeter of a Polygon

サンプルが意味もなく少ない。
あと問題文が分かりにくい。エスパーした。

## 問題

多角形$P$の頂点が、時計周りに与えられる。
自己交差等はない。
多角形$P$の周囲の長さを答えよ。

## 実装

``` haskell
module Main where
import Control.Applicative
import Control.Monad

distance :: (Int, Int) -> (Int, Int) -> Double
distance (ax, ay) (bx, by) = sqrt . fromIntegral $ (bx - ax) ^ 2 + (by - ay) ^ 2
perimeter :: [(Int, Int)] -> Double
perimeter p = sum $ zipWith distance p (last p : p)

main :: IO ()
main = do
    n <- readLn
    p <- replicateM n $ do
        [x, y] <- map read . words <$> getLine
        return (x, y)
    print $ perimeter p
```

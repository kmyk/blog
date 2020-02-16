---
layout: post
alias: "/blog/2016/03/28/hackerrank-lambda-calculi-march-2016-lambda-march-compute-the-area-of-a-polygon/"
date: 2016-03-28T15:26:46+09:00
tags: [ "competitive", "writeup", "hackerrank", "lambda-calculi", "haskell" ]
"target_url": [ "https://www.hackerrank.com/contests/lambda-calculi-march-2016/challenges/lambda-march-compute-the-area-of-a-polygon" ]
---

# Lambda Calculi - March 2016: Compute the Area of a Polygon

## 問題

多角形$P$の頂点が、時計周りに与えられる。
自己交差等はない。
多角形$P$の面積を答えよ。

## 実装

``` haskell
module Main where
import Control.Applicative
import Control.Monad

cross :: (Int, Int) -> (Int, Int) -> Double
cross (ax, ay) (bx, by) = (/ 2) . fromIntegral $ ax * by - ay * bx
area :: [(Int, Int)] -> Double
area p = sum $ zipWith cross p (last p : p)

main :: IO ()
main = do
    n <- readLn
    p <- replicateM n $ do
        [x, y] <- map read . words <$> getLine
        return (x, y)
    print . area $ reverse p
```

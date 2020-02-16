---
layout: post
redirect_from:
  - /blog/2016/03/28/hackerrank-lambda-calculi-march-2016-functions-or-not/
date: 2016-03-28T15:25:59+09:00
tags: [ "competitive", "writeup", "hackerrank", "lambda-calculi", "haskell" ]
"target_url": [ "https://www.hackerrank.com/contests/lambda-calculi-march-2016/challenges/functions-or-not" ]
---

# Lambda Calculi - March 2016: Functions or Not?

問題文が不十分。サンプルまで見ればなんとか察することはできる。

## 問題

関係$R \subseteq \omega \times \omega$が与えられる。$\omega = \\{ 0, 1, 2, \dots, n, \dots \\}$である。
$R$が部分関数$R : \omega \dashrightarrow \omega$を成すかどうか、つまり、$\forall x. ((\exists y. (x, y) \in R) \to (\exists! y, (x, y) \in R))$を判定せよ。

## 実装

``` haskell
module Main where
import Control.Applicative
import Control.Monad
import Data.List

isFunction :: Int -> [(Int, Int)] -> Bool
isFunction n = (== n) . length . nub . sort . map fst

main :: IO ()
main = do
    t <- readLn
    replicateM_ t $ do
        n <- readLn
        r <- replicateM n $ do
            [x, y] <- map read . words <$> getLine
            return (x, y)
        putStrLn (if isFunction n r then "YES" else "NO")
```

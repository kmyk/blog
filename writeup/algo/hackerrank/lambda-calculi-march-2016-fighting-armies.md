---
layout: post
alias: "/blog/2016/03/28/hackerrank-lambda-calculi-march-2016-fighting-armies/"
title: "Lambda Calculi - March 2016: Fighting Armies"
date: 2016-03-28T15:27:36+09:00
tags: [ "competitive", "writeup", "hackerrank", "lambda-calculi", "haskell", "lazy-evaluation" ]
"target_url": [ "https://www.hackerrank.com/contests/lambda-calculi-march-2016/challenges/fighting-armies" ]
---

TLEするから悩んでたら、入力取る部分が問題だった。
2-3 finger treeとかleftist heapとかを調べてたのは何だったのか。
でも楽しかったから良い。好き。

## 問題

やるだけ。haskellの遅延評価は賢いので、単にそのまま書くだけで間に合う。
ただしhaskellの`String`による入出力は遅いので、`BS.getLine`と`BS.readInt`を使う必要がある。

## 実装

leftist heap版も書いたが、ほぼ[Leftist Heap - 言語ゲーム](http://d.hatena.ne.jp/propella/20091123/p1)を写しただけなので省略。
あるいは`Data.Map.Map Int Int`を使ってもよい。

``` haskell
module Main where
import Control.Applicative
import Control.Monad
import Data.Maybe
import qualified Data.Vector.Mutable as V
import qualified Data.ByteString.Char8 as BS

readInts :: IO [Int]
readInts = map (fst . fromJust . BS.readInt) . BS.words <$> BS.getLine

insertSortedList :: Ord a => a -> [a] -> [a]
insertSortedList x [] = [x]
insertSortedList x (y : ys) = if x < y
    then y : insertSortedList x ys
    else x : y : ys
mergeSortedList :: Ord a => [a] -> [a] -> [a]
mergeSortedList [] ys = ys
mergeSortedList xs [] = xs
mergeSortedList (x : xs) (y : ys) = if x < y
    then y : mergeSortedList (x : xs) ys
    else x : mergeSortedList xs (y : ys)


findStrongest :: V.IOVector [Int] -> Int -> IO ()
findStrongest a i = BS.putStrLn . BS.pack . show . head =<< V.read a i
strongestDied :: V.IOVector [Int] -> Int -> IO ()
strongestDied a i = V.modify a tail i
recruit :: V.IOVector [Int] -> Int -> Int -> IO ()
recruit a i c = V.modify a (insertSortedList c) i
merge :: V.IOVector [Int] -> Int -> Int -> IO ()
merge a i j = do
    ys <- V.read a j
    V.write a j undefined
    V.modify a (\ xs -> mergeSortedList xs ys) i

main :: IO ()
main = do
    [n, q] <- readInts
    a <- V.replicate n []
    replicateM_ q $ do
        qs <- readInts
        case qs of
            [1, i] -> findStrongest a (i-1)
            [2, i] -> strongestDied a (i-1)
            [3, i, c] -> recruit a (i-1) c
            [4, i, j] -> merge a (i-1) (j-1)
```

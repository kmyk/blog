---
layout: post
redirect_from:
  - /writeup/algo/hackerrank/lambda-calculi-march-2016-lambda-march-concave-polygon/
  - /blog/2016/03/28/hackerrank-lambda-calculi-march-2016-lambda-march-concave-polygon/
date: 2016-03-28T15:27:06+09:00
tags: [ "competitive", "writeup", "hackerrank", "lambda-calculi", "haskell" ]
"target_url": [ "https://www.hackerrank.com/contests/lambda-calculi-march-2016/challenges/lambda-march-concave-polygon" ]
---

# Lambda Calculi - March 2016: Concave Polygon

問題文は不明瞭。
相変わらずサンプルは少ない。
まじめにやる気が起きず、何度か書いたことあるしと思って、ぐぐってそのまま貼り付けた。

## 問題

多角形$P$の頂点が、時計周りに与えられる。
多角形$P$が[concave](https://en.wikipedia.org/wiki/Concave_polygon)であるか判定せよ。

## 解法

それを取り除いても多角形としての形が変わらない頂点が存在するのか、するならどう答えるべきなのか、判断できないがテストケースに含まれるようなので、通るまで適当にする。
自己交差はないらしい。

## 実装

``` haskell
module Main where
import Control.Applicative
import Control.Monad
import Data.Function
import Data.List
import Data.Tuple

-- https://en.wikibooks.org/wiki/Algorithm_Implementation/Geometry/Convex_hull/Monotone_chain

-- Coordinate type
type R = Integer

-- Vector / point type
type R2 = (R, R)

-- Checks if it's shortest to rotate from the OA to the OB vector in a clockwise
-- direction.
clockwise :: R2 -> R2 -> R2 -> Bool
clockwise o a b = (a `sub` o) `cross` (b `sub` o) < 0

-- 2D cross product.
cross :: R2 -> R2 -> R
cross (x1, y1) (x2, y2) = x1 * y2 - x2 * y1

-- Subtract two vectors.
sub :: R2 -> R2 -> R2
sub (x1, y1) (x2, y2) = (x1 - x2, y1 - y2)

-- Implements the monotone chain algorithm
convexHull :: [R2] -> [R2]
convexHull [] = []
convexHull [p] = [p]
convexHull points = lower ++ upper
  where
    sorted = sort points
    lower = chain sorted
    upper = chain (reverse sorted)

chain :: [R2] -> [R2]
chain = go []
  where
    -- The first parameter accumulates a monotone chain where the most recently
    -- added element is at the front of the list.
    go :: [R2] -> [R2] -> [R2]
    go acc@(r1:r2:rs) (x:xs) =
      if clockwise r2 r1 x
        -- Made a clockwise turn - remove the most recent part of the chain.
        then go (r2:rs) (x:xs)
        -- Made a counter-clockwise turn - append to the chain.
        else go (x:acc) xs
    -- If there's only one point in the chain, just add the next visited point.
    go acc (x:xs) = go (x:acc) xs
    -- No more points to consume - finished!  Note: the reverse here causes the
    -- result to be consistent with the other examples (a ccw hull), but
    -- removing that and using (upper ++ lower) above will make it cw.
    go acc [] = reverse $ tail acc


isConcave :: [R2] -> Bool
isConcave p = length p /= length (convexHull $ map (\ (x, y) -> (x, - y)) p)

main :: IO ()
main = do
    n <- readLn
    p <- replicateM n $ do
        [x, y] <- map read . words <$> getLine
        return (x, y)
    putStrLn (if isConcave p then "YES" else "NO")
```

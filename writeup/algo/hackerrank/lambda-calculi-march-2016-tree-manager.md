---
layout: post
redirect_from:
  - /blog/2016/03/28/hackerrank-lambda-calculi-march-2016-tree-manager/
date: 2016-03-28T15:27:21+09:00
tags: [ "competitive", "writeup", "hackerrank", "lambda-calculi", "haskell", "zipper" ]
"target_url": [ "https://www.hackerrank.com/contests/lambda-calculi-march-2016/challenges/tree-manager" ]
---

# Lambda Calculi - March 2016: Tree manager

これはかなり好きな問題。でもちょっとテストケースが弱い気がする。

## 解法

[zipper](https://wiki.haskell.org/Zipper)。

>   -   A single node will never have more than $10$ children.

なので、やればよい。以下のような構造になる。

``` haskell
data Tree = Tree
    { value :: Int
    , children :: [Tree]
    }

data Zipper = Zipper
    { tree :: Tree
    , lefts :: [Tree]
    , rights :: [Tree]
    , parents :: [([Tree], Int, [Tree])]
    }
```

## 実装

`reverse`を忘れないように。

``` haskell
module Main where
import Control.Monad
import Data.List

data Tree = Tree
    { value :: Int
    , children :: [Tree]
    }

data Zipper = Zipper
    { tree :: Tree
    , lefts :: [Tree]
    , rights :: [Tree]
    , parents :: [([Tree], Int, [Tree])]
    }

initialTree :: Zipper
initialTree = Zipper (Tree 0 []) [] [] []

command :: Zipper -> IO Zipper
command z = do
    let t = tree z
    l <- getLine
    case words l of
        ["change", x] ->
            return z { tree = t { value = read x } }
        ["print"] -> do
            print $ value t
            return z
        ["visit", "left"] -> do
            let (l : ls) = lefts z
            return z { lefts = ls, tree = l, rights = t : rights z }
        ["visit", "right"] -> do
            let (r : rs) = rights z
            return z { lefts = t : lefts z, tree = r, rights = rs }
        ["visit", "parent"] -> do
            let ((ls, v, rs) : ps) = parents z
            return $ Zipper (Tree v (reverse (lefts z) ++ [t] ++ rights z)) ls rs ps
        ["visit", "child", n] -> do
            let (ls, t' : rs) = splitAt (read n - 1) (children t)
            return $ Zipper t' (reverse ls) rs ((lefts z, value t, rights z) : parents z)
        ["insert", "left",  x] ->
            return z { lefts = Tree (read x) [] : lefts z }
        ["insert", "right", x] ->
            return z { rights = Tree (read x) [] : rights z }
        ["insert", "child", x] ->
            return z { tree = t { children = Tree (read x) [] : children t } }
        ["delete"] -> do
            let ((ls, v, rs) : ps) = parents z
            return $ Zipper (Tree v (reverse (lefts z) ++ rights z)) ls rs ps

main :: IO ()
main = do
    n <- readLn
    foldl (>>=) (return initialTree) $ replicate n command
    return ()
```

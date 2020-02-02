---
layout: post
alias: "/blog/2017/08/15/abc-070-c/"
date: "2017-08-15T13:15:48+09:00"
title: "AtCoder Beginner Contest 070: C - Multiple Clocks"
tags: [ "competitive", "writeup", "atcoder", "abc" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc070/tasks/abc070_c" ]
---

LCMするだけなのでawkあたりで書きたかったが、$10^{18}$が溢れるのでだめだった。

## implementation

``` haskell
#!/usr/bin/env runhaskell
import Control.Monad
main :: IO ()
main = do
    n <- readLn
    t <- replicateM n readLn
    let result = foldr1 lcm t :: Int
    print result
```

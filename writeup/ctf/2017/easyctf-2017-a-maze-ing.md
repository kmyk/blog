---
layout: post
alias: "/blog/2017/03/22/easyctf-2017-a-maze-ing/"
date: "2017-03-22T16:32:19+09:00"
title: "EasyCTF 2017: A-maze-ing"
tags: [ "ctf", "writeup", "easyctf", "misc", "guessing" ]
---

なぜかflag提出の結果が帰ってくるのがすごく遅いのに、こういう問題を出してくるのはすごいですね。

## problem

迷路があるのでそのスタートからゴールへの道筋を答えよ。
上下左右の移動を`i` `k` `j` `l` (vim風だが`h`は使わないやつ)で示して`flag{` `}`で囲んで提出せよ。

(問題文はだいたい上みたいなもの。肝心の迷路は与えられない)

## solution

flag: `easyctf{kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk}`

何を投げてもflagが外れだったときのメッセージで `The maze is longer than that.` って言われる。
他の問題だと `Nope.` と言われるので怪しい。
そこで適当に長いflagを提出してみたら `You guessed right!` と通った。

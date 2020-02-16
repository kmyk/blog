---
layout: post
redirect_from:
  - /writeup/algo/atcoder/atc-002-b/
  - /blog/2016/04/11/atc-002-b/
date: 2016-04-11T06:48:07+09:00
tags: [ "competitive", "writeup", "atcoder", "atc" ]
"target_url": [ "https://beta.atcoder.jp/contests/atc002/tasks/atc002_b" ]
---

# AtCoder Typical Contest 002 B - n^p mod m

pythonの`pow`って対数時間なんだったっけ、と思いながらやったら通った。
ちゃんと繰り返し二乗法してくれるようだ。

## 実装

48byte 1位タイ

``` python
n,m,p=map(int,input().split());print(pow(n,p,m))
```

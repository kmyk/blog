---
layout: post
redirect_from:
  - /blog/2017/11/10/hackerrank-optimization-oct17-castle-towers/
date: "2017-11-10T22:51:39+09:00"
tags: [ "competitive", "writeup", "hackerrank" ]
"target_url": [ "https://www.hackerrank.com/contests/optimization-oct17/challenges/castle-towers" ]
---

# HackerRank Performance Optimization: A. Castle Towers

## 感想

Performance Optimizationというから実行速度で点数あるいはペナルティが付くと思っていましたが、単にTLEコードがtextareaに始めから書いてあるというだけでした。
気付かずACした後に最適化して再提出みたいな真似をしてしまった。

## problem

高さが最大のものの数を答えよ。

## solution

sortで$O(N \log N)$だと遅いので、$O(N)$にする。

## implementation

``` c++
...

#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
int castleTowers(int n, vector<int> const & ar) {
    int maxi = 0;
    int cnt = 0;
    repeat (i, n) {
        if (maxi < ar[i]) {
            maxi = ar[i];
            cnt = 1;
        } else {
            cnt += (maxi == ar[i]);
        }
    }
    return cnt;
}

...
```

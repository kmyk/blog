---
layout: post
redirect_from:
  - /writeup/algo/hackerrank/optimization-oct17-collatz-sequence-sum/
  - /blog/2017/11/10/hackerrank-optimization-oct17-collatz-sequence-sum/
date: "2017-11-10T22:51:48+09:00"
tags: [ "competitive", "writeup", "hackerrank", "memoization" ]
"target_url": [ "https://www.hackerrank.com/contests/optimization-oct17/challenges/collatz-sequence-sum" ]
---

# HackerRank Performance Optimization: B. Collatz Sequence Sum

## problem

$g(K)$を$K$以下の自然数でCollatz数列が最長となるようなもの。複数あるなら最大。
$A, B$で生成される数列$N\_1, \dots, N\_T$に対し$\sum g(N\_i)$を答えよ。

## solution

いい感じにメモ化する。`map`を入れてだいたい$O(N \log N)$とかなのでは。

## implementation

``` c++
...

#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
int collatzSequenceSum(int T, int A, int B) {
    constexpr int mod = 5003;
    vector<int> g(mod); {
        map<int, int> memo;
        memo[0] = 0;
        memo[1] = 1;
        function<int (int)> collatzSequenceLen = [&](int n) {
            if (not memo.count(n)) {
                memo[n] = n % 2 == 0 ?
                    1 + collatzSequenceLen(n / 2) :
                    1 + collatzSequenceLen(3 * n + 1);
            }
            return memo[n];
        };
        repeat (i, mod) {
            if (i >= 1) {
                g[i] = collatzSequenceLen(i) >= collatzSequenceLen(g[i - 1]) ?
                    i :
                    g[i - 1];
            }
        }
    }
    int n = 0;
    int result = 0;
    while (T --) {
        n = (A * n + B) % mod;
        result += g[n];
    }
    return result;
}

...
```

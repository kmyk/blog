---
layout: post
alias: "/blog/2016/05/23/hackerrank-may-world-codesprint-absolute-permutation/"
title: "HackerRank May World CodeSprint: Absolute Permutation"
date: 2016-05-23T01:50:01+09:00
tags: [ "competitive", "writeup", "hackerrank", "world-codesprint" ]
"target_url": [ "https://www.hackerrank.com/contests/may-world-codesprint/challenges/absolute-permutation" ]
---

## problem

$[1,N]$の順列$P$で、$\forall i \in [1,N].\; \|\operatorname{pos}\_P(i) - i\| = K$となるような$P$で、辞書順最小のものを答えよ。
ただし$\operatorname{pos}\_P(P_i) = i$。

## solution

The number $i \in [1,N]$ needs to be placed at $i \pm K$-th of $P$.

So the number $1$ has to be $P\_{K+1}$ and $K+1$ does $P_1$.
Solving such constraints, there exists a unique $P$ if $2K \mid N$, and doesn't exist if $2K \nmid N$.

## implementation

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
int main() {
    int testcases; cin >> testcases;
    while (testcases --) {
        int n, k; cin >> n >> k;
        vector<int> p(n);
        if (k == 0) {
            repeat (i,n) p[i] = i;
        } else if (n % (2*k) == 0) {
            repeat (i,n/(2*k)) {
                int offset = i * 2*k;
                repeat (j,k) {
                    p[offset + j] = offset + k + j;
                    p[offset + k + j] = offset + j;
                }
            }
        } else {
            p.resize(1);
            p[0] = -2;
        }
        repeat (i,p.size()) { if (i) cout << ' '; cout << p[i] + 1; } cout << endl;
    }
    return 0;
}
```

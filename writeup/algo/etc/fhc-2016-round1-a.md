---
layout: post
alias: "/blog/2016/01/18/fhc-2016-round1-a/"
title: "Facebook Hacker Cup 2016 Round 1 Coding Contest Creation"
date: 2016-01-18T01:17:27+09:00
tags: [ "competitive", "writeup", "facebook-hacker-cup", "greedy" ]
---

## [Coding Contest Creation](https://www.facebook.com/hackercup/problem/798506286925018/)

### 問題

問題の列が与えられる。
問題にはそれぞれ難しさが定まっている。
この列を前から4つずつに切り分けてコンテストの列を作る。
しかしコンテストに使う問題には条件がある。
A,B,C,Dの問題に関して、難易度が狭義単調増加で、隣接する問題の難易度の差が10を越えてはならない。
これを満たすように新規の問題を列に挿入する。挿入する問題の数の最小を答えよ。

### 解法

貪欲。

前から見ていく。
残っている中で1番手前の問題をA問題とする。
2番目をB問題にする。できなければ追加する。
追加できない場合は、最初に選んだ問題はA問題でなくてB問題だったことにする。
こんな感じのことを繰り返して全部使えばよい。

### 実装

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
int solve() {
    int n; cin >> n;
    vector<int> ds(n); repeat (i,n) cin >> ds[i];
    int result = 0;
    int k = 0; // in [0,4)
    int i = 0; // in [0,n)
    int d = -1; // in [1,100]
    while (i < n) {
        if (k == 0) {
            d = ds[i ++];
        } else {
            if (d < ds[i] and ds[i] <= d+10) {
                d = ds[i ++];
            } else {
                result += 1;
                d += 10;
            }
        }
        k = (k+1) % 4;;
    }
    if (k != 0) result += 4-k;
    return result;
}
int main() {
    int testcases; cin >> testcases;
    repeat (testcase, testcases) {
        cout << "Case #" << testcase+1 << ": " << solve() << endl;
    }
    return 0;
}
```

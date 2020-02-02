---
layout: post
alias: "/blog/2015/11/21/abc-031-c/"
title: "AtCoder Beginner Contest 031 C - 数列ゲーム"
date: 2015-11-21T23:09:42+09:00
tags: [ "competitive", "writeup", "atcoder", "abc" ]
"target_url": [ "!-- more --" ]
---

## [C - 数列ゲーム](https://beta.atcoder.jp/contests/abc031/tasks/abc031_c) {#c}

### 解法

$N \le 50$と小さい。やるだけ。

### 実装

pythonでもよかったかも。

``` c++
#include <iostream>
#include <vector>
#include <climits>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
using namespace std;
int main() {
    int n; cin >> n;
    vector<int> a(n); repeat (i,n) cin >> a[i];
    pair<int,int> result = { INT_MIN, INT_MIN }; // (first player, second player)
    repeat (i,n) {
        int fst_best = INT_MIN;
        int snd_best = INT_MIN;
        repeat (j,n) if (i != j) {
            int l = min(i,j); // [l, r)
            int r = max(i,j) + 1;
            int fst = 0;
            int snd = 0;
            repeat_from (k,l,r) {
                (((k-l) % 2) ? snd : fst) += a[k];
            }
            if (snd_best < snd) {
                fst_best = fst;
                snd_best = snd;
            }
        }
        result = max(result, make_pair(fst_best, snd_best));
    }
    cout << result.first << endl;
    return 0;
}
```

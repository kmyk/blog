---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-090-c/
  - /blog/2018/04/09/arc-090-c/
date: "2018-04-09T23:19:34+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc090/tasks/arc090_a" ]
---

# AtCoder Regular Contest 090: C - Candies

## solution

DP。組合せ${}\_nC\_r$を求めるときの雰囲気でやる。$O(N^2)$。

最長経路問題に落としてDAGなのでBellman-Ford法でもできるなあとは思ったが$O(N^3)$なので無駄。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;
template <class T> inline void chmax(T & a, T const & b) { a = max(a, b); }

int main() {
    // input
    int n; cin >> n;
    vector<int> a0(n); REP (i, n) cin >> a0[i];
    vector<int> a1(n); REP (i, n) cin >> a1[i];
    // solve
    vector<int> acc0(n + 1); partial_sum(ALL(a0), acc0.begin() + 1);
    vector<int> acc1(n + 1); partial_sum(ALL(a1), acc1.begin() + 1);
    int result = 0;
    REP (i, n) {
        chmax(result, (acc0[i + 1] - acc0[0]) + (acc1[n] - acc1[i]));
    }
    // output
    cout << result << endl;
    return 0;
}
```

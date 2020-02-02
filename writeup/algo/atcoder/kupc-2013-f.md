---
layout: post
alias: "/blog/2017/05/12/kupc-2013-f/"
date: "2017-05-12T20:28:53+09:00"
title: "京都大学プログラミングコンテスト2013: F - ７歳教"
tags: [ "competitive", "writeup", "atcoder", "kupc", "dp", "graph", "warshall-floyd" ]
"target_url": [ "https://beta.atcoder.jp/contests/kupc2013/tasks/kupc2013_f" ]
---

これも$3$WA。

## solution

各惑星$i$について、時刻$r\_i$に惑星$i$に滞在するときのそれまでの$7$歳で過ごす年数の最大値を$\mathrm{dp}\_i$とする。
これをWarshall-Floyd法っぽく更新して$O(N^3)$。

$7$歳で過ごすのはどの惑星ででも価値が同じである。
これにより、惑星$i$で$7$歳の直後に惑星$j$で$7$歳するとき、もし惑星$i$を出発する時刻が$r\_i$でないならこれを$r\_i$へずらしても結果は変わらない。
効いているのはこの性質。

## implementation

DPを$0$で初期化するとだめ。時刻$r\_i$までに惑星$i$に辿り着けるとは限らない。

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }
int main() {
    // input
    int n, s; scanf("%d%d", &n, &s); -- s;
    vector<int> l(n), r(n); repeat (i,n) scanf("%d%d", &l[i], &r[i]);
    auto w = vectors(n, n, int()); repeat (i,n) repeat (j,n) scanf("%d", &w[i][j]);
    // compute
    // // Warshall Floyd
    repeat (k,n) {
        repeat (i,n) {
            repeat (j,n) {
                setmin(w[i][j], w[i][k] + w[k][j]);
            }
        }
    }
    // // dp
    vector<int> dp(n, -1);
    repeat (i,n) {
        if (w[s][i] <= r[i]) {
            dp[i] = r[i] - max(l[i], w[s][i]);
        }
    }
    repeat (k,n) {
        repeat (i,n) if (dp[i] != -1) {
            repeat (j,n) {
                if (r[i] + w[i][j] <= r[j]) {
                    setmax(dp[j], dp[i] + r[j] - max(l[j], r[i] + w[i][j]));
                }
            }
        }
    }
    // output
    int result = *whole(max_element, dp);
    printf("%d\n", result);
    return 0;
}
```

---
layout: post
title: "技術室奥プログラミングコンテスト #3: F - 天使とふすま"
date: 2018-08-02T08:36:32+09:00
tags: [ "competitive", "writeup", "atcoder", "tkppc", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/tkppc3/tasks/tkppc3_f" ]
---

## solution

貪欲。$O(n \log n)$。

適当に並べた列を修正することを考えよう。
隣接する$2$要素$(A_i, B_i)$と$(A_j, B_j)$を考えたとき、これら以外の部分に関わらず$A_i B_j \le A_j B_i$なら$i$が$j$の前であるべき。
この比較は$\frac{A_i}{B_i} \le \frac{A_j}{B_j}$と同値であり、また必ずしも隣接している必要はない。
よって$g(i) = \frac{A_i}{B_i}$の順に使用すれば全体としても最適である。

一般に「隣接する$2$要素$x, y$を考えたとき$g(x), g(y)$の順に並ぶように交換すれば目的関数$F$が改善される」を仮定して「$g(x)$の順に整列するのが最適」を言える。
隣接する$2$要素で交換できるものの交換のみで整列(つまりbubble sort)ができるので、任意の列より整列済みの列の方が小さい。

## note

$\frac{A_i}{B_i}$の順でソートするやつはさすがに典型だし蟻本にまったく同じのがありそう

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;

int main() {
    // input
    int n; cin >> n;
    vector<int> a(n), b(n);
    REP (i, n) {
        cin >> a[i] >> b[i];
    }

    // solve
    vector<int> order(n);
    iota(ALL(order), 0);
    sort(ALL(order), [&](int i, int j) {
        return a[i] * b[j] < a[j] * b[i];
    });
    ll answer = 0;
    ll acc_a = 0;
    for (int i : order) {
        answer += acc_a * b[i];
        acc_a += a[i];
    }

    // answer
    cout << answer << endl;
    return 0;
}
```

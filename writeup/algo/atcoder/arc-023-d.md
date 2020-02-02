---
layout: post
alias: "/blog/2016/03/29/arc-023-d/"
title: "AtCoder Regular Contest 023 D - GCD区間"
date: 2016-03-29T17:56:25+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "gcd", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc023/tasks/arc023_4" ]
---

解けないと思って解説を見たが、ねばっていれば解けていたかもしれない。
$2^n$の増加が急なのは当然すぐ出てくるが、$n$の約数の個数の増加が緩やかなのは知っているのになかなか出てこない。

## 解法

dp。$O(N \log \max A)$。

$\gcd [l,l+1), \gcd [l,l+2), \dots, \gcd [l,n)$が高々$\log a_l$種類の値しか含まないことを使う。$\gcd$による列は単調減少で、減少の回数は$\log a_l$の約数の数を越えないからである。

$a_i$を右端とする区間でその$\gcd$が$j$であるものを$dp\_{i,j}$とし、これを更新する。
$a\_{i+1}$を右端とする区間のそれは、$a\_i$を右端とする区間から計算できる。

## 実装

$a_i \le 10^9$なので`vector`で持つとTLEやMLEする。

``` c++
#include <iostream>
#include <vector>
#include <unordered_map>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
int gcd(int a, int b) { if (b < a) swap(a,b); while (a) { int c = a; a = b % c; b = c; } return b; }
int main() {
    int n, m; cin >> n >> m;
    vector<int> as(n); repeat (i,n) cin >> as[i];
    unordered_map<int,ll> acc, cur, prv;
    for (int a : as) {
        cur.swap(prv);
        cur.clear();
        cur[a] += 1;
        acc[a] += 1;
        for (auto p : prv) {
            int b, cnt; tie(b, cnt) = p;
            int c = gcd(a, b);
            cur[c] += cnt;
            acc[c] += cnt;
        }
    }
    repeat (i,m) {
        int x; cin >> x;
        cout << acc[x] << endl;
    }
    return 0;
}
```

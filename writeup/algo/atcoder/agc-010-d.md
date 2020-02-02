---
layout: post
alias: "/blog/2017/02/17/agc-010-d/"
date: "2017-02-17T14:34:17+09:00"
title: "AtCoder Grand Contest 010: D - Decrementing"
tags: [ "competitive", "writeup", "atcoder", "game" ]
---

1000点にしてはかなり簡単だった。
この回はBもCも難しくて未提出撤退をした記憶があるのになあ。

## solution

最大公約数で割る操作が勝敗に影響するのは偶数で割るときだけ。$O(N \log A_i)$。

まず最大公約数で割る操作を行わないとして考えよう。
この場合は単純で、$\sum_i (A_i - 1)$の偶奇が必勝手番を決定する。

最大公約数で割る操作はこの$\sum_i (A_i - 1)$の偶奇を入れ替えうる。
最大公約数$g$が奇数のとき、$kg - k = k(g - 1)$は偶数なので$\sum_i (A_i - 1)$の偶奇は不変。
よって$g$が偶数の場合だけに注目すればよい。
また、先手であれ後手であれ、相手と同様に数字を選んでいけば$g$が偶数の割る操作は回避できる。
例外として、先攻の初手においてはこれが発生しうる。

$\sum_i (A_i - 1)$の偶奇を確認し先手必勝でないなら偶数で割ることを試みる、を再帰的にやればよい。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <numeric>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;
int gcd(int a, int b) { while (a) { b %= a; swap(a, b); } return b; }
bool solve(int n, vector<int> & a) {
    ll sum = whole(accumulate, a, 0ll);
    bool is_first = (sum - n) % 2;
    int even = whole(count_if, a, [&](int ai) { return ai % 2 == 0; });
    auto odd = whole(find_if,  a, [&](int ai) { return ai % 2 == 1; });
    if (not is_first and even == n-1 and *odd != 1) {
        -- (*odd);
        int d = a[0]; repeat (i,n) d = gcd(d, a[i]);
        repeat (i,n) a[i] /= d;
        return not solve(n, a);
    } else {
        return is_first;
    }
}
int main() {
    int n; cin >> n;
    vector<int> a(n); repeat (i,n) cin >> a[i];
    cout << (solve(n, a) ? "First" : "Second") << endl;
    return 0;
}
```

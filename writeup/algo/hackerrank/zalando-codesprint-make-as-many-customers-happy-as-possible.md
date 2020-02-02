---
layout: post
alias: "/blog/2016/06/05/hackerrank-zalando-codesprint-make-as-many-customers-happy-as-possible/"
title: "HackerRank Zalando CodeSprint: Make Our Customers Happy"
date: 2016-06-05T19:17:59+09:00
tags: [ "competitive", "writeup", "hackerrank", "greedy" ]
"target_url": [ "https://www.hackerrank.com/contests/zalando-codesprint/challenges/make-as-many-customers-happy-as-possible-" ]
---

## problem

商品が$3$種類ある。それぞれ在庫が$N_a, N_b, N_c$個ある。
注文が$N$個あって、それぞれの商品を高々$1$個まで要求する。
全て満たすことのできる注文の数の最大値を答えよ。

## solution

Fulfill the given orders greedily, in the order of size from small. $O(N)$.

At first, fulfill the orders `A`, `B` and `C`, while it's possible.
Then, fulfill the orders `A,B`, `A,C` and `B,C`, in certain optimal order.
There are $3! (= 6)$ ways to fulfill there orders so it can be searched by bruteforce.
Finally, fulfill the order `A,B,C`.

## implementation

``` c++
#include <iostream>
#include <algorithm>
#include <array>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
template <class T> bool setmax(T & l, T const & r) { if (not (l < r)) return false; l = r; return true; }
template <class T> bool setmin(T & l, T const & r) { if (not (r < l)) return false; l = r; return true; }
using namespace std;
int main() {
    int na, nb, nc; cin >> na >> nb >> nc;
    int n; cin >> n;

    int qa = 0;
    int qb = 0;
    int qc = 0;
    int qab = 0;
    int qbc = 0;
    int qca = 0;
    int qabc = 0;
    repeat (i,n) {
        string s; cin >> s;
        bool a = s.find('A') != string::npos;
        bool b = s.find('B') != string::npos;
        bool c = s.find('C') != string::npos;
        if (    a and not b and not c) ++ qa;
        if (not a and     b and not c) ++ qb;
        if (not a and not b and     c) ++ qc;
        if (    a and     b and not c) ++ qab;
        if (not a and     b and     c) ++ qbc;
        if (    a and not b and     c) ++ qca;
        if (    a and     b and     c) ++ qabc;
    }

    auto fulfill = [](int & acc, int & na, int & nb, int & nc, bool a, bool b, bool c, int cnt) {
        if (a) setmin(cnt, na);
        if (b) setmin(cnt, nb);
        if (c) setmin(cnt, nc);
        acc += cnt;
        if (a) na -= cnt;
        if (b) nb -= cnt;
        if (c) nc -= cnt;
    };

    int ans = 0;
    array<int,3> xs; repeat (i,3) xs[i] = i;
    do {
        int acc = 0;
        int a = na;
        int b = nb;
        int c = nc;
        fulfill(acc, a, b, c, 1, 0, 0, qa);
        fulfill(acc, a, b, c, 0, 1, 0, qb);
        fulfill(acc, a, b, c, 0, 0, 1, qc);
        for (int x : xs) {
            if (x == 0) fulfill(acc, a, b, c, 1, 1, 0, qab);
            if (x == 1) fulfill(acc, a, b, c, 0, 1, 1, qbc);
            if (x == 2) fulfill(acc, a, b, c, 1, 0, 1, qca);
        }
        fulfill(acc, a, b, c, 1, 1, 1, qabc);
        setmax(ans, acc);
    } while (next_permutation(xs.begin(), xs.end()));

    cout << ans << endl;
    return 0;
}
```

---
layout: post
title: "AtCoder Grand Contest 026: C - String Coloring"
date: 2018-08-09T21:34:32+09:00
tags: [ "competitive", "writeup", "atcoder", "agc", "string", "meet-in-the-middle" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc026/tasks/agc026_c" ]
---

## solution

文字列$S$を前半後半の半分に割って半分全列挙。
後半を反転させると前半と一致する形になって上手くいく。
$O(2^N)$。

## note

どうやったらこれが思い付くのか分からない。
たしかに半分全列挙したい制約であるし、とりあえず$S$を半分にしてみたら偶然に解法を拾うということはあるかもしれないが、数分以内に気付けるものとは思えない。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;

void split(int n, string const & t, unordered_map<string, int> & f) {
    REP (x, 1 << n) {
        string a, b;
        REP (i, n) {
            (x & (1 << i) ? a : b) += t[i];
        }
        f[a + "/" + b] += 1;
    }
}

int main() {
    // input
    int n; cin >> n;
    string s; cin >> s;

    // solve
    string t1 = s.substr(0, n);
    string t2 = s.substr(n);
    reverse(ALL(t2));
    unordered_map<string, int> f, g;
    split(n, t1, f);
    split(n, t2, g);
    ll cnt = 0;
    for (auto const & it : f) {
        if (g.count(it.first)) {
            cnt += (ll)it.second * g[it.first];
        }
    }

    // output
    cout << cnt << endl;
    return 0;
}
```

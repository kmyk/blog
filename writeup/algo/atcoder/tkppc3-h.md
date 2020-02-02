---
layout: post
title: "技術室奥プログラミングコンテスト #3: H - 新入生歓迎数列 - Hard"
date: 2018-08-02T10:04:47+09:00
tags: [ "competitive", "writeup", "atcoder", "tkppc" ]
"target_url": [ "https://beta.atcoder.jp/contests/tkppc3/tasks/tkppc3_h" ]
---

## solution

$30$bitの上半分と下半分をそれぞれまとめて作る。
$A_1$を$1 = 2^0$や$2^{15}$にしてこれを$A_2$に$2^{15}$回足し、それぞれの時点で一致する他の$A_j$ ($j \ge 2$)に足し込む。
$A_1 = 1$の制約は必須。
クエリ数は$2 \cdot 2^{15} + 2N + \alpha$。
一般にはbit数$B$と分割数$K$で$O(K(2^{B/K} + N))$クエリ。

$N \le 2 \times 10^5$ にも関わらず $Q \le 5.5 \times 10^5$ であるので$1$要素あたり高々$2.5$回で構築しないといけない。
となると選択肢はbitsetとしての包含関係の順に上手くやるか、上で述べた解法のどちらか。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;

vector<pair<int, int> > solve(int n, const vector<int> & a) {
    // precondition
    constexpr int SIZE = 30;
    assert (a[0] == 1);
    assert (*max_element(ALL(a)) < (1 << SIZE));

    // prepare api
    vector<int> b(n, 0);
    vector<pair<int, int> > ops;
    auto op1 = [&](int x) {
        ops.emplace_back(x, -1);
        b[x] = 1;
    };
    auto op2 = [&](int y, int z) {
        ops.emplace_back(y, z);
        b[y] += b[z];
    };

    // categorize a_i's
    vector<vector<int> > lo(1 << (SIZE / 2));
    vector<vector<int> > hi(1 << (SIZE / 2));
    REP3 (x, 2, n) {
        constexpr int HALF = SIZE / 2;
        constexpr int HALF_MASK = (1 << HALF) - 1;
        lo[a[x] &  HALF_MASK].push_back(x);
        hi[a[x] >> HALF     ].push_back(x);
    }

    // construct lower half
    op1(0);
    op1(1);
    REP3 (s, 1, 1 << (SIZE / 2)) {
        assert (b[1] == s);
        for (int x : lo[s]) {
            op2(x, 1);
        }
        op2(1, 0);
    }

    // construct upper half
    REP (i, SIZE / 2) {
        op2(0, 0);
    }
    REP3 (s, 1, 1 << (SIZE / 2)) {
        assert (b[1] == (s << (SIZE / 2)));
        for (int x : hi[s]) {
            op2(x, 1);
        }
        op2(1, 0);
    }

    // construct a_0 and a_1
    op1(0);
    int i = 1 << SIZE;
    while (not (a[1] & i)) i >>= 1;
    op1(1);
    i >>= 1;
    for (; i; i >>= 1) {
        op2(1, 1);
        if (a[1] & i) op2(1, 0);
    }

    // postcondition
    assert (ops.size() <= 550000);
    assert (b == a);
    return ops;
}

int main() {
    // input
    int n; cin >> n;
    vector<int> a(n);
    REP (i, n) cin >> a[i];

    // solve
    vector<pair<int, int> > ops = solve(n, a);

    // output
    cout << ops.size() << endl;
    for (auto op : ops) {
        if (op.second == -1) {
            cout << 1 << " " << op.first + 1 << endl;
        } else {
            cout << 2 << " " << op.first + 1 << " " << op.second + 1 << endl;
        }
    }
    return 0;
}
```

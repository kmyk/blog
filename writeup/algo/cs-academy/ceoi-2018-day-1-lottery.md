---
layout: post
date: 2018-08-15T04:05:54+09:00
tags: [ "competitive", "writeup", "csacademy", "cumulative-sum", "optimization" ]
"target_url": [ "https://csacademy.com/contest/ceoi-2018-day-1/task/lottery/" ]
---

# CS Academy CEOI 2018 Day 1: Lottery

## solution

区間$[x, x + l)$と区間$[y, y + l)$の不一致の数が分かっているとすると、区間$[x + 1, x + l + 1)$と区間$[y + 1, y + l + 1)$の不一致の数が$O(1)$で求まる。
これをする。
不一致の数は$\le k_j$なのでimos法っぽくしてまとめる。
計算量は $O(n^2 \log q + q)$。

時間/空間ともに定数倍がそこそこきつい。
差分の表を作ってその累積和という方向から考えてそのまま実装してMLEした。
imos法部分でmapを雑に使うとTLEした。

## note

コンテスト中の気持ちは次のような順でした: 「全然分からん」「もしかして典型やるだけ」「バグ」「ML厳しい」「TLまであるのかよ」「これが一番解かれてないのなぜ」

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;

map<int, vector<int> > solve(int n, int l, vector<int> const & a, set<int> const & k) {
    map<int, vector<int> > cnt;
    for (int k_j : k) {
        cnt[k_j] = vector<int>(n - l + 1);
    }
    REP3 (shift, 1, n - l + 1) {
        int k = 0;
        REP (i, l) {
            k += (a[i] != a[shift + i]);
        }
        REP (x, (n - l + 1) - shift) {
            auto it = cnt.lower_bound(k);
            if (it != cnt.end()) {
                ++ it->second[x];
                ++ it->second[x + shift];
            }
            if (x + 1 < (n - l + 1) - shift) {
                k -= (a[x] != a[x + shift]);
                k += (a[x + l] != a[x + shift + l]);
            }
        }
    }
    for (auto it = next(cnt.begin()); it != cnt.end(); ++ it) {
        auto & cur = it->second;
        auto & prv = prev(it)->second;
        REP (x, n - l + 1) {
            cur[x] += prv[x];
        }
    }
    return cnt;
}

int main() {
    // input
    int n, l; cin >> n >> l;
    vector<int> a(n);
    REP (i, n) cin >> a[i];
    int q; cin >> q;
    vector<int> k(q);
    REP (j, q) cin >> k[j];

    // solve
    auto cnt = solve(n, l, a, set<int>(ALL(k)));

    // output
    for (int k_j : k) {
        REP (x, n - l + 1) {
            if (x) cout << ' ';
            cout << cnt[k_j][x];
        }
        cout << endl;
    }
    return 0;
}
```

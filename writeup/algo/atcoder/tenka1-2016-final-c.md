---
layout: post
date: 2018-07-07T03:00:16+09:00
tags: [ "competitive", "writeup", "atcoder", "tenka1", "rolling-hash", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/tenka1-2016-final/tasks/tenka1_2016_final_c" ]
---

# 天下一プログラマーコンテスト2016本戦: C - たんごたくさん

## 解法

rolling hashやるだけDP。計算量は<span>$O(|S| \cdot (M + |P|))$</span>あるいは<span>$O(|S| \cdot |P| \log M)$</span>と嘘っぽいが通る。
time limit $5$秒に対し$1.2$秒なので余裕はあり、下手なtrie <span>$O(|S| \cdot |P|)$</span>(想定解ぽい)より速い。

rolling hashの定数に$(10^9 + 7, 10^4 + 7)$を使うと衝突し、かといって複数にするとTLEする。
法を`int`に収める利点はないので、定数のおすすめは$(10^{15} + 37, 10^4 + 7)$。
なおshift操作はできない。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using ll = long long;
using namespace std;
template <class T> inline void chmax(T & a, T const & b) { a = max(a, b); }

constexpr uint64_t prime = 1000000000000037;
constexpr uint64_t base = 10007;
uint64_t rolling_hash_push(uint64_t hash, uint8_t c) {
    return (hash * base + c) % prime;
}
uint64_t rolling_hash(const string & s) {
    uint64_t hash = 0;
    for (char c : s) {
        hash = rolling_hash_push(hash, c);
    }
    return hash;
}

int main() {
    // input
    string s; cin >> s;
    int m; cin >> m;
    vector<string> p(m);
    REP (i, m) cin >> p[i];
    vector<int> w(m);
    REP (i, m) cin >> w[i];

    // solve
    int len = 0;
    REP (i, m) {
        chmax<int>(len, p[i].size());
    }

    vector<vector<int> > lookup(len + 1);
    vector<uint64_t> hash(m);
    REP (i, m) {
        lookup[p[i].size()].push_back(i);
        hash[i] = rolling_hash(p[i]);
    }

    vector<ll> dp(s.length() + 1);
    REP (i, s.length()) {
        chmax(dp[i + 1], dp[i]);
        uint64_t h = 0;
        REP (j, len) if (j < (int)s.length() - i) {
            h = rolling_hash_push(h, s[i + j]);
            for (int k : lookup[j + 1]) if (hash[k] == h) {
                chmax(dp[i + j + 1], dp[i] + w[k]);
            }
        }
    }

    // output
    cout << dp.back() << endl;
    return 0;
}
```

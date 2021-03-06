---
redirect_from:
  - /writeup/algo/codeforces/1028-d/
layout: post
date: 2018-08-29T03:36:26+09:00
tags: [ "competitive", "writeup", "codeforces", "counting" ]
"target_url": [ "http://codeforces.com/contest/1028/problem/D" ]
---

# Codeforces AIM Tech Round 5 (rated, Div. 1 + Div. 2): D. Order book

## 問題

株の売買の操作の列が与えられる。
しかし売りか買いかの情報が落とされ値段の情報だけ与えられるので、復元先としてありえる列の数を数えよ。

## 解法

`set<int> sell, unknown, buy;` と持つ。
`ACCEPT` クエリが来たらその $$p$$ との大小の差で他はすべて `SELL` か `BUY` か定まる。
$$O(n \log n)$$。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
using namespace std;

template <int32_t MOD>
struct mint {
    int64_t data;
    mint() = default;
    mint(int64_t value) : data(value) {}
    inline mint<MOD> operator + (mint<MOD> other) const { int64_t c = this->data + other.data; return mint<MOD>(c >= MOD ? c - MOD : c); }
    inline mint<MOD> operator * (mint<MOD> other) const { int64_t c = this->data * int64_t(other.data) % MOD; return mint<MOD>(c < 0 ? c + MOD : c); }
    inline mint<MOD> & operator += (mint<MOD> other) { this->data += other.data; if (this->data >= MOD) this->data -= MOD; return *this; }
    inline mint<MOD> & operator *= (mint<MOD> other) { this->data = this->data * int64_t(other.data) % MOD; if (this->data < 0) this->data += MOD; return *this; }
};

constexpr int MOD = 1e9 + 7;

mint<MOD> solve(int n, vector<pair<bool, int> > const & offers) {
    mint<MOD> cnt = 1;
    set<int> sell, unknown, buy;
    for (auto offer : offers) {
        bool is_add; int p; tie(is_add, p) = offer;
        if (is_add) {
            if (not sell.empty() and *sell.begin() < p) {
                sell.insert(p);
            } else if (not buy.empty() and p < *buy.rbegin()) {
                buy.insert(p);
            } else {
                unknown.insert(p);
            }
        } else {
            if (sell.count(p)) {
                if (p != *sell.begin()) return 0;
                sell.erase(p);
            } else if (buy.count(p)) {
                if (p != *buy.rbegin()) return 0;
                buy.erase(p);
            } else {
                assert (unknown.count(p));
                cnt *= 2;
            }
            for (int q : unknown) {
                if (q < p) {
                    buy.insert(q);
                } else if (p < q) {
                    sell.insert(q);
                }
            }
            unknown.clear();
        }
    }
    cnt *= unknown.size() + 1;
    return cnt;
}

int main() {
    int n; cin >> n;
    vector<pair<bool, int> > offers(n);
    REP (i, n) {
        string s; int p; cin >> s >> p;
        assert (s == "ADD" or s == "ACCEPT");
        offers[i] = make_pair(s == "ADD", p);
    }
    cout << solve(n, offers).data << endl;
    return 0;
}
```

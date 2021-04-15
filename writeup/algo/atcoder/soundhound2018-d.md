---
redirect_from:
  - /writeup/algo/atcoder/soundhound2018-d/
layout: post
date: 2018-10-26T06:02:34+09:00
tags: [ "competitive", "writeup", "atcoder", "soundhound", "dp", "max", "linearity" ]
"target_url": [ "https://beta.atcoder.jp/contests/soundhound2018/tasks/soundhound2018_d" ]
---

# SoundHound Inc. Programming Contest 2018 (春): D - 建物

## 解法

### 概要

$$H = 1$$としても本質は同じ。
とりあえず$$O(W^2)$$のDPを書いて適当にすると、線形性により$$2$$変数関数の最大値を$$1$$変数化し差分更新できて$$O(W)$$になる。
全体で$O(HW)$。

### 詳細

次のようにおく:

-   $$\hat{l _ y}(x)$$: 部屋$$(y, x)$$に既にいる時点から始めて、好きなだけ左へ行ってから戻ってくるときの獲得金額の最大値
-   $$\hat{m _ y}(r) - \hat{m _ y}(r + 1)$$: 部屋$$(y, l)$$に既にいる時点から始めて、部屋$$(y, r)$$までまっすぐ移動するときの獲得金額。ただし $$l \lt r$$
-   $$\hat{r _ y}(x)$$: 部屋$$(y, x)$$に既にいる時点から始めて、好きなだけ右へ行ってから戻ってくるときの獲得金額の最大値

このときDPで求める関数は

$$\mathrm{dp}(y + 1, x) = \max \left\\{
    \max \left\\{ \mathrm{dp}(y, x') + \hat{l _ y}(x') + \hat{m _ y}(x  + 1) - \hat{m _ y}(x') + \hat{r _ y}(x ) \mid x' \le x \right\\},
    \max \left\\{ \mathrm{dp}(y, x') + \hat{l _ y}(x ) + \hat{m _ y}(x' + 1) - \hat{m _ y}(x ) + \hat{r _ y}(x') \mid x \le x' \right\\} \right\\}$$

であるが、これは

$$\mathrm{dp}(y + 1, x) = \max \left\\{
    \max \left\\{ \mathrm{dp}(y, x') + \hat{l _ y}(x') - \hat{m _ y}(x') \mid x' \le x \right\\} + \hat{m _ y}(x + 1) + \hat{r _ y}(x),
    \max \left\\{ \mathrm{dp}(y, x') + \hat{m _ y}(x' + 1) + \hat{r _ y}(x') \mid x \le x' \right\\} + \hat{l _ y}(x) - \hat{m _ y}(x) \right\\}$$

と書き直せる。
内側の最大化対象の関数が$$x'$$のみの関数になったため、異なる$$x$$同士でその計算結果を使い回せて$$O(W)$$に落ちる。

## メモ

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
using ll = long long;
using namespace std;
template <class T, class U> inline void chmax(T & a, U const & b) { a = max<T>(a, b); }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

constexpr ll INF = (ll)1e18 + 9;
vector<ll> solve(int h, int w, vector<vector<ll> > const & ps, vector<vector<ll> > const & fs) {
    vector<ll> cur(w, - INF), prv;
    cur[0] = 0;

    REP (y, h) {
        auto const & p = ps[y];
        auto const & f = fs[y];
        vector<ll> m(w + 1);
        REP (x, w) {
            m[x + 1] = m[x] + p[x] - f[x];
        }
        vector<ll> l(w);
        REP (x, w - 1) {
            l[x + 1] = max(0ll, l[x] + p[x] - f[x] - f[x + 1]);
        }
        vector<ll> r(w);
        REP_R (x, w - 1) {
            r[x] = max(0ll, r[x + 1] + p[x + 1] - f[x + 1] - f[x]);
        }

        cur.swap(prv);
        cur.assign(w, - INF);

/*
        // O(W^2)
        REP (x, w) {
            REP (x1, w) {
                if (x1 < x) {
                    chmax(cur[x], prv[x1] + l[x1] + m[x + 1] - m[x1] + r[x]);
                } else {
                    chmax(cur[x], prv[x1] + l[x] + m[x1 + 1] - m[x] + r[x1]);
                }
            }
        }
*/

        // O(W)
        ll acc = - INF;
        REP (x, w) {
            chmax(cur[x], acc + m[x + 1] + r[x]);
            chmax(acc, prv[x] + l[x] - m[x]);
        }
        acc = - INF;
        REP_R (x, w) {
            chmax(acc, prv[x] + r[x] + m[x + 1]);
            chmax(cur[x], acc + l[x] - m[x]);
        }
    }
    return cur;
}

int main() {
    int h, w; cin >> h >> w;
    auto p = vectors(h, w, 0ll);
    auto f = vectors(h, w, 0ll);
    REP (y, h) REP (x, w) cin >> p[y][x];
    REP (y, h) REP (x, w) cin >> f[y][x];
    auto answer = solve(h, w, p, f);
    for (auto it : answer) cout << it << endl;
    return 0;
}
```

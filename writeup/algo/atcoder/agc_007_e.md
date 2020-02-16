---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc-007-e/
  - /blog/2017/07/26/agc-007-e/
date: "2017-07-26T07:11:02+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "tree", "dp", "shakutori-method" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc007/tasks/agc007_e" ]
---

# AtCoder Grand Contest 007: E - Shik and Travel

TLEとWAをたくさんした。ほとんどの場合は愚直DPの方が速いのだが、それがどんなケースで遅いのかは分からなかった。

## solution

動的計画法。二分探索。$O(\log (\log N \max v\_i) \cdot N^2)$ぐらいで抑えられる。

まず問題を整理する。
一度入った部分木の外にでるのはその部分木の葉を使い終わった後だけとして、葉から葉への移動を繰り返し、葉から葉への移動の経路長の最大値を最小化する。
ただし根に繋がる移動の重みは考えなくてよい。

すぐに思い付くのが次のようなDP: 各部分木について、その木の外から葉へ出入りするような道の重みの対$(a, b)$とそのときの部分木の中での経路長の最大値の最小値$c$を考え、可能な組$(a, b, c)$を必要なだけ列挙。
$(a, b, c) \le \mathbb{N}^3$の自然に半順序を考え、列挙された中で極小でないものはそれより自明に良いものがあるのだから無視してよい。
これは答えを導くが、最悪の場合の状態数が大きくなりすぎる。また左右の部分木から列挙された状態を$X, Y$としたとき、生成が愚直に$\\{ f(x, y) \mid x \in X, y \in Y \\}$を尽くすしかないので不要なものの除去と合わせると$O(\|X\|^2\|Y\|^2)$になる。
そこで二分探索。$c$の上界を固定してやれば状態からこれを落とせる。
加えて状態が$(a, b)$という形になるので、列挙して不要なものを絞った後に整列すれば凸な形になる。
ここで上手くしゃくとり法をすると計算量が$O(\|X\| + \|Y\|)$まで落ちて、これで間に合う。

## implementation

``` c++
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <functional>
#include <tuple>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f, x, ...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }

template <typename UnaryPredicate>
ll binsearch(ll l, ll r, UnaryPredicate p) { // [l, r), p is monotone
    assert (l < r);
    -- l;
    while (r - l > 1) {
        ll m = (l + r) / 2;
        (p(m) ? r : l) = m;
    }
    return r; // = min { x in [l, r) | p(x) }, or r
}

void flip(vector<pair<ll, ll> > & it) {
    repeat (i, it.size()) swap(it[i].first, it[i].second);
    whole(reverse, it);
}
bool pred(vector<vector<pair<int, int> > > const & g, ll limit) {
    function<vector<pair<ll, ll> > (int, int)> dfs = [&](int v, int parent) {
        if (g[v].size() == 1) {
            vector<pair<ll, ll> > result;
            result.emplace_back(0, 0);
            return result;
        }
        vector<pair<ll, ll> > left, right;
        for (auto edge : g[v]) {
            int w, value; tie(w, value) = edge;
            if (w == parent) continue;
            auto & it = (left.empty() ? left : right);
            it = dfs(w, v);
            repeat (i, it.size()) {
                it[i].first  += value;
                it[i].second += value;
            }
        }
        vector<pair<ll, ll> > result;
        auto func = [&]() {
            int i = 0;
            int j = right.size() - 1;
            for (; i < left.size(); ++ i) {
                while (j >= 0 and left[i].first + right[j].first > limit) -- j;
                if (j < 0) break;
                ll a = left[i].second;
                ll b = right[j].second;
                if (a > b) swap(a, b);
                result.emplace_back(a, b);
            }
        };
        func();
        flip(left);
        func();
        flip(right);
        func();
        flip(left);
        func();
        whole(sort, result);
        result.erase(whole(unique, result, [&](auto x, auto y) { return x.second <= y.second; }), result.end());
        return result;
    };
    return not dfs(0, -1).empty();
}

constexpr ll inf = ll(1e18)+9;
int main() {
    int n; scanf("%d", &n);
    vector<vector<pair<int, int> > > g(n);
    repeat (i, n - 1) {
        int a, v; scanf("%d%d", &a, &v);
        g[a - 1].emplace_back(i + 1, v);
        g[i + 1].emplace_back(a - 1, v);
    }
    ll result = binsearch(0, inf, [&](ll limit) {
        return pred(g, limit);
    });
    printf("%lld\n", result);
    return 0;
}
```

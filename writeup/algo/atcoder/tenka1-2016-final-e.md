---
redirect_from:
layout: post
date: 2018-07-12T22:25:22+09:00
tags: [ "competitive", "writeup", "atcoder", "tenka1", "convex-hull-trick" ]
"target_url": [ "https://beta.atcoder.jp/contests/tenka1-2016-final/tasks/tenka1_2016_final_e" ]
---

# 天下一プログラマーコンテスト2016本戦: E - 串焼きパーティ

## solution

CHT貼るだけ。$O(NL\log L)$。

まず考えるのは串を刺す位置は初期位置における$1, 2, \dots, L$番目の部分の位置だけで十分であること。
それぞれの肉はそこそこ独立なので、それぞれの肉と串の位置の対すべてについてその最小コストを求めたい。
つまり<span>$f(i, j) = \min \\{ a_{i, k} + (k - j)^2 \mid k \\}$</span>と置いて$\mathrm{ans} = \min \\{ \sum_i f(i, j) \mid j \\}$。
さてここで<span>$f(i, j) = j^2 + \min \\{ (- 2k) \cdot j + (a_{i, k} + k^2) \mid k \\}$</span>であるので、これは単にconvex hull trickをすればよい。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

struct line_t { ll a, b; };  // y = ax + b
bool operator < (line_t lhs, line_t rhs) { return make_pair(- lhs.a, lhs.b) < make_pair(- rhs.a, rhs.b); }
struct rational_t { ll num, den; };
rational_t make_rational(ll num, ll den = 1) {
    if (den < 0) { num *= -1; den *= -1; }
    return { num, den };
}
bool operator < (rational_t lhs, rational_t rhs) {
    if (lhs.num ==   LLONG_MAX or rhs.num == - LLONG_MAX) return false;
    if (lhs.num == - LLONG_MAX or rhs.num ==   LLONG_MAX) return true;
    return lhs.num * rhs.den < rhs.num * lhs.den;
}

struct convex_hull_trick {
    convex_hull_trick() {
        lines.insert({ + LLONG_MAX, 0 });  // sentinels
        lines.insert({ - LLONG_MAX, 0 });
        cross.emplace(make_rational(- LLONG_MAX), (line_t) { - LLONG_MAX, 0 });
    }
    void add_line(ll a, ll b) {
        auto it = lines.insert({ a, b }).first;
        if (not is_required(*prev(it), { a, b }, *next(it))) {
            lines.erase(it);
            return;
        }
        cross.erase(cross_point(*prev(it), *next(it)));
        {  // remove right lines
            auto ju = prev(it);
            while (ju != lines.begin() and not is_required(*prev(ju), *ju, { a, b })) -- ju;
            cross_erase(ju, prev(it));
            it = lines.erase(++ ju, it);
        }
        {  // remove left lines
            auto ju = next(it);
            while(next(ju) != lines.end() and not is_required({ a, b }, *ju, *next(ju))) ++ ju;
            cross_erase(++ it, ju);
            it = prev(lines.erase(it, ju));
        }
        cross.emplace(cross_point(*prev(it), *it), *it);
        cross.emplace(cross_point(*it, *next(it)), *next(it));
    }
    ll get_min(ll x) const {
        line_t f = prev(cross.lower_bound(make_rational(x)))->second;
        return f.a * x + f.b;
    }
private:
    set<line_t> lines;
    map<rational_t, line_t> cross;
    template <typename Iterator>
    void cross_erase(Iterator first, Iterator last) {
        for (; first != last; ++ first) {
            cross.erase(cross_point(*first, *next(first)));
        }
    }
    rational_t cross_point(line_t f1, line_t f2) const {
        if (f1.a ==   LLONG_MAX) return make_rational(- LLONG_MAX);
        if (f2.a == - LLONG_MAX) return make_rational(  LLONG_MAX);
        return make_rational(f1.b - f2.b, f2.a - f1.a);
    }
    bool is_required(line_t f1, line_t f2, line_t f3) const {
        if (f1.a == f2.a and f1.b <= f2.b) return false;
        if (f1.a == LLONG_MAX or f3.a == - LLONG_MAX) return true;
        return (f2.a - f1.a) * (f3.b - f2.b) < (f2.b - f1.b) * (f3.a - f2.a);
    }
};

ll sq(ll x) { return x * x; }

int main() {
    // input
    int n, l; cin >> n >> l;
    auto a = vectors(n, l, int());
    REP (y, n) REP (x, l) cin >> a[y][x];

    // solve
    vector<ll> acc(l);
    REP (y, n) {
        convex_hull_trick cht;
        REP (x, l) {
            cht.add_line(- 2 * x, a[y][x] + sq(x));
        }
        REP (x, l) {
            acc[x] += cht.get_min(x) + sq(x);
        }
    }

    // output
    cout << *min_element(ALL(acc)) << endl;
    return 0;
}
```

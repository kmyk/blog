---
layout: post
title: "CODE FESTIVAL 2018 Final: C - Telephone Charge"
date: 2018-11-22T20:39:22+09:00
tags: [ "competitive", "writeup", "atcoder", "code-festival", "convex-hull-trick" ]
"target_url": [ "https://beta.atcoder.jp/contests/code-festival-2018-final/tasks/code_festival_2018_final_c" ]
---

## 解法

### 概要

定額部分と従量課金部分に分け、それぞれでの最小値を求めればよい。
丁寧に書けば $$O(N + M)$$ でできるはず。

## メモ

-   実装はCHTを貼ってさぼりました
-   関数の形が「ramp関数を平行移動したもの」であるので楽になっている。
    この問題は「ramp関数を平行移動してできる関数の族 $$f_1, f_2, \dots, f_N$$ に対し $$F(x) = \min \left\{ f_i(x) \mid i \le N \right\}$$ とおいて $$F(x_1), F(g_2), \dots, F(g_M)$$ を求める問題」であるが「区分的に一次関数であり連続な関数の族 $$f_1, f_2, \dots, f_N$$ に対し $$\dots$$」まで一般化するとけっこう手間で、折れ線グラフのマージ処理を区間最大値クエリとか使って頑張ることになりそう。実質幾何。
    もしこれを解くなら「区間上で定義された一次関数であるような関数の族 $$f_1 : [l_1, r_1) \to R, f_2 : [l_2, r_2) \to R, \dots, f_N : [l_2, r_2) \to R$$ に対し $$\dots$$」まで一般化しても同じ。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;
template <class T> using reversed_priority_queue = priority_queue<T, vector<T>, greater<T> >;
template <class T, class U> inline void chmin(T & a, U const & b) { a = min<T>(a, b); }

/**
 * @note y = ax + b
 */
struct line_t { ll a, b; };
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

/*
 * @sa http://d.hatena.ne.jp/sune2/20140310/1394440369
 * @sa http://techtipshoge.blogspot.jp/2013/06/convex-hull-trickdequepop-back.html
 * @sa http://satanic0258.hatenablog.com/entry/2016/08/16/181331
 * @sa http://wcipeg.com/wiki/Convex_hull_trick
 * @note verified at http://codeforces.com/contest/631/submission/31828502
 */
struct convex_hull_trick {
    convex_hull_trick() {
        lines.insert({ + LLONG_MAX, 0 });  // sentinels
        lines.insert({ - LLONG_MAX, 0 });
        cross.emplace(make_rational(- LLONG_MAX), (line_t) { - LLONG_MAX, 0 });
    }
    /**
     * @note O(log n)
     */
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
    /**
     * @note O(log n)
     */
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

int main() {
    // input
    int n; cin >> n;
    vector<int> a(n), b(n);
    REP (i, n) cin >> a[i] >> b[i];
    int m; cin >> m;
    vector<int> t(m);
    REP (j, m) cin >> t[j];

    // solve
    vector<ll> answer(m, LLONG_MAX);
    priority_queue<tuple<int, char, int> > que;
    reversed_priority_queue<tuple<int, char, int> > rque;
    REP (i, n) {
        que .emplace(a[i], 'a', i);
        rque.emplace(a[i], 'A', i);
    }
    REP (j, m) {
        que .emplace(t[j], 'B', j);
        rque.emplace(t[j], 'b', j);
    }
    ll min_b = LLONG_MAX;
    while (not que.empty()) {
        char type; int k; tie(ignore, type, k) = que.top();
        que.pop();
        if (type == 'a') {
            chmin(min_b, b[k]);
        } else if (type == 'B') {
            chmin(answer[k], min_b);
        }
    }
    convex_hull_trick cht;  // CHT is essentially unnecessary
    cht.add_line(1, *max_element(ALL(b)));
    while (not rque.empty()) {
        char type; int k; tie(ignore, type, k) = rque.top();
        rque.pop();
        if (type == 'A') {
            cht.add_line(1, b[k] - a[k]);
        } else if (type == 'b') {
            chmin(answer[k], cht.get_min(t[k]));
        }
    }

    // output
    REP (j, m) {
        cout << answer[j] << endl;
    }
    return 0;
}
```

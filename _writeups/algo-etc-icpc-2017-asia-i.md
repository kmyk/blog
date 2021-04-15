---
layout: post
redirect_from:
  - /writeup/algo/etc/icpc-2017-asia-i/
  - /blog/2017/12/19/icpc-2017-asia-i/
date: "2017-12-19T03:49:25+09:00"
tags: [ "competitive", "writeup", "icpc", "icpc-asia", "segment-tree", "range-sum-query", "imos", "scheduling" ]
---

# AOJ 1386 / ACM-ICPC 2017 Asia Tsukuba Regional Contest: I. Starting a Scenic Railroad Service

-   <http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=1386>
-   <http://judge.u-aizu.ac.jp/onlinejudge/cdescription.jsp?cid=ICPCOOC2017&pid=I>

## problem

列車の座席の予約を考える。
座席は複数列ある。
乗客が$n$人いて、それぞれいずれかの座席の区間$[a\_i, b\_i)$を占有したいと考えている。
乗客はランダムな順番で予約を入れる。
次のような方針で予約を受けるとき、全員の予約を必ず受け入れるには座席は最低何列必要か。

1.  何列目を割り当てるかを客が指定する。
2.  何列目を割り当てるかをこちらが自由に決めてよい。

## solution

考えるべき区間の全体の長さを$w$としておく。座圧すれば$w \le 2n$である。

方針$1$について。
区間$[a, b)$ごとにこれと交差するような区間の数を数え、その最大値を答えればよい。補集合、つまり交差しないような区間の数を考えればよい。binary indexed treeやsegment tree。$O((n + w) \log w)$。

方針$2$について。
位置$x$ごとに何人の客がその位置を利用したいかを数え、その最大値を答えればよい。imos法。$O(n + w)$。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = (n) - 1; (i) >= 0; -- (i))
#define ALL(x) begin(x), end(x)
using namespace std;
template <class T> inline void chmax(T & a, T const & b) { a = max(a, b); }

template <class Monoid>
struct segment_tree {
    typedef typename Monoid::underlying_type underlying_type;
    int n;
    vector<underlying_type> a;
    Monoid mon;
    segment_tree() = default;
    segment_tree(int a_n, underlying_type initial_value = Monoid().unit(), Monoid const & a_mon = Monoid()) : mon(a_mon) {
        n = 1; while (n < a_n) n *= 2;
        a.resize(2 * n - 1, mon.unit());
        fill(a.begin() + (n - 1), a.begin() + ((n - 1) + a_n), initial_value); // set initial values
        REP_R (i, n - 1) a[i] = mon.append(a[2 * i + 1], a[2 * i + 2]); // propagate initial values
    }
    void point_set(int i, underlying_type z) { // 0-based
        a[i + n - 1] = z;
        for (i = (i + n) / 2; i > 0; i /= 2) { // 1-based
            a[i - 1] = mon.append(a[2 * i - 1], a[2 * i]);
        }
    }
    underlying_type range_concat(int l, int r) { // 0-based, [l, r)
        underlying_type lacc = mon.unit(), racc = mon.unit();
        for (l += n, r += n; l < r; l /= 2, r /= 2) { // 1-based loop, 2x faster than recursion
            if (l % 2 == 1) lacc = mon.append(lacc, a[(l ++) - 1]);
            if (r % 2 == 1) racc = mon.append(a[(-- r) - 1], racc);
        }
        return mon.append(lacc, racc);
    }
};
struct plus_monoid {
    typedef int underlying_type;
    int unit() const { return 0; }
    int append(int a, int b) const { return a + b; }
};

int policy_1(int n, vector<int> const & a, vector<int> const & b) {
    int b_max = *max_element(ALL(b));
    segment_tree<plus_monoid> l(b_max + 1);  // can be a BIT
    segment_tree<plus_monoid> r(b_max + 1);
    REP (i, n) {
        l.point_set(b[i], l.range_concat(b[i], b[i] + 1) + 1);
        r.point_set(a[i], r.range_concat(a[i], a[i] + 1) + 1);
    }
    int result = 0;
    REP (i, n) {
        chmax(result, n - l.range_concat(0, a[i] + 1) - r.range_concat(b[i], b_max + 1));
    }
    return result;
}

int policy_2(int n, vector<int> const & a, vector<int> const & b) {
    int b_max = *max_element(ALL(b));
    vector<int> imos(b_max + 1);
    REP (i, n) {
        imos[a[i]] += 1;
        imos[b[i]] -= 1;
    }
    REP (x, b_max) {
        imos[x + 1] += imos[x];
    }
    return *max_element(ALL(imos));
}

int main() {
    // input
    int n; scanf("%d", &n);
    vector<int> a(n), b(n);
    REP (i, n) scanf("%d%d", &a[i], &b[i]);
    // solve
    int s1 = policy_1(n, a, b);
    int s2 = policy_2(n, a, b);
    // output
    printf("%d %d\n", s1, s2);
    return 0;
}
```

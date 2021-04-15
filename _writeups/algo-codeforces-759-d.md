---
layout: post
redirect_from:
  - /writeup/algo/codeforces/759-d/
  - /blog/2018/03/31/cf-759-d/
date: "2018-03-31T01:27:51+09:00"
tags: [ "competitive", "writeup", "codeforces", "dp", "segment-tree", "inline-dp" ]
"target_url": [ "http://codeforces.com/contest/759/problem/D" ]
---

# Codeforces Round #393 (Div. 1) (8VC Venture Cup 2017 - Final Round Div. 1 Edition): D. Bacterial Melee

## problem

文字列$s$が与えられる。
操作$s\_{i - 1} \gets s\_i$と操作$s\_{i + 1} \gets s\_i$を好きな回数好きな順序で行なって得られる文字列の種類の数はいくつか。

## solution

実家DP。$O(n^2 \log n)$。

前処理として同じ文字が連続する場合は実質的にひとつに潰してよい。
次のDPが立つ: 左から順に決めていき(文字を潰した後の文字列で)$i$文字目を最後に使って$j \le n$文字決まったところまでの文字列の種類の数を$\mathrm{dp}(i, j)$とする。
ただし同じ文字列を複数回数えないようにするため、$i$文字目を使ってから次に$i'$文字目を使うときは最も最初、つまり$s\_i \ne s\_{i'}$かつ$\lnot \exists k. i \lt k \lt i' \land s\_k = s\_{i'}$でなければならない。
愚直に更新すると$O(n^3)$。貰う形にしてsegment木で加速すれば$O(n^2 \log n)$で通る。


## note

-   「$i$文字目を最後に使った」ではなく「文字$c$を最後に使った」で状態を圧縮するのはだめな方針
-   segment木の操作を雑にやるとTLE
-   文字種$L = 26$が乗って$O(L n^2 \log n)$なものは間に合わなかった
-   kmjpさんの解説を読んだ: <http://kmjp.hatenablog.jp/entry/2017/01/27/0930>

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;

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
    // fast methods
    inline underlying_type point_get(int i) {
        return a[i + n - 1];
    }
    inline void point_set_primitive(int i, underlying_type z) {
        a[i + n - 1] = z;
    }
    void point_set_commit() {
        REP_R (i, n - 1) a[i] = mon.append(a[2 * i + 1], a[2 * i + 2]);
    }
};
struct plus_monoid {
    typedef ll underlying_type;
    ll unit() const { return 0; }
    ll append(ll a, ll b) const { return a + b; }
};

constexpr int MOD = 1e9 + 7;
int solve(int n, string const & s) {
    typedef segment_tree<plus_monoid> segtree;
    segtree cur(n + 1);
    cur.point_set(0, 1);
    REP (j, n) {
        segtree prv = cur;
        cur = segtree(n + 1);
        array<int, 26> last;
        fill(ALL(last), -1);
        REP (i, n) {
            int c = s[i] - 'a';
            ll v1 = prv.range_concat(last[c] + 1, i);
            ll v2 = prv.point_get(i);
            cur.point_set_primitive(i, (v1 + v2) % MOD);
            last[c] = i;
        }
        cur.point_set_commit();
    }
    return (cur.range_concat(0, n + 1) % MOD + MOD) % MOD;
}

int main() {
    int n; cin >> n;
    string s; cin >> s;
    int answer = solve(n, s);
    cout << answer << endl;
    return 0;
}
```

---
layout: post
date: 2018-08-29T02:10:23+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "segment-tree", "gcd" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc017/tasks/arc017_4" ]
redirect_from:
  - /writeup/algo/atcoder/arc-017-d/
---

# AtCoder Regular Contest 017: D - ARCたんクッキー

## 問題

区間加算更新/区間GCD取得のクエリがたくさん与えられるので処理せよ

## 解法

差分のGCDを持っていい感じに。
$$O((N + M) \log N)$$。

GCD $$d = \mathrm{gcd}(a_l, a _ {l + 1}, \dots, a _ {r - 1})$$ とする。
区間中のすべての $$i, i + 1 \in [l, r)$$ に対し $$d \mid | a _ {i + 1} - a_i |$$ なのはすぐに気付ける。
となると差分のGCD $$d' = \mathrm{gcd}(|a _ {l + 1} - a_l|, \dots, |a _ {r - 1} - a _ {r - 2}|)$$ から目的の $$d$$ を復元したくなる。
ここで実は任意の $$i \in [l, r)$$ に対し $$d = \mathrm{gcd}(i, d')$$ が示せる。
実験してみて上手く引き当てればよい。
よって区間加算更新のsegment木と区間GCD取得のsegment木をそれぞれ持てば計算できる。

証明をしておこう。
$$d \mid \mathrm{gcd}(a_i, d')$$ と $$\mathrm{gcd}(a_i, d') \mid d$$ を示せばよい。
前者はすべての $$i \in [l, r)$$ に対し $$d \mid a_i$$ なのでそれら差分も $$d$$ で割り切れるため。
後者について。 $$i \in [l, r)$$ を固定し任意の $$j \in [l, r)$$ に対し $$\mathrm{gcd}(a_i, d') \mid a_j$$ を示せばよい。
議論は同様なので $$i \lt j$$ とおく。
$$a_j = (a_j - a _ {j - 1}) + (a _ {j - 1} + a _ {j - 2}) + \dots + (a _ {i + 1} - a_i) + a_i$$ である。
右辺の項はすべて $$\mathrm{gcd}(a_i, d') \mid a_j$$ で割り切れるため左辺もこれで割り切れる。
ただし $$a _ {i + 1} - a_i \le 0$$ でも問題ないことに注意。
これで示せた。

## メモ

-   $$\mathrm{gcd}(|a _ {l + 1} - a_l|, \dots, |a _ {r - 1} - a _ {r - 2}|)$$ を実験してみるところまでは行ったが気付けなかった。実験コードがバグってたのが一因か
-   「全てのメンテナンスを実施する日において、メンテナンス実施後、どの製造機も製造するクッキーの枚数が $$1$$ 枚以上 $$10^9$$ 枚以下である。」これ罠だったりしそうと思ってたらどうやらそうらしい

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
using ll = long long;
using namespace std;

template <class Monoid>
struct segment_tree {
    typedef typename Monoid::underlying_type underlying_type;
    int n;
    vector<underlying_type> a;
    const Monoid mon;
    segment_tree() = default;
    segment_tree(int a_n, underlying_type initial_value = Monoid().unit(), Monoid const & a_mon = Monoid()) : mon(a_mon) {
        n = 1; while (n < a_n) n *= 2;
        a.resize(2 * n - 1, mon.unit());
        fill(a.begin() + (n - 1), a.begin() + ((n - 1) + a_n), initial_value); // set initial values
        REP_R (i, n - 1) a[i] = mon.append(a[2 * i + 1], a[2 * i + 2]); // propagate initial values
    }
    void point_set(int i, underlying_type z) { // 0-based
        assert (0 <= i and i <= n);
        a[i + n - 1] = z;
        for (i = (i + n) / 2; i > 0; i /= 2) { // 1-based
            a[i - 1] = mon.append(a[2 * i - 1], a[2 * i]);
        }
    }
    underlying_type range_concat(int l, int r) { // 0-based, [l, r)
        assert (0 <= l and l <= r and r <= n);
        underlying_type lacc = mon.unit(), racc = mon.unit();
        for (l += n, r += n; l < r; l /= 2, r /= 2) { // 1-based loop, 2x faster than recursion
            if (l % 2 == 1) lacc = mon.append(lacc, a[(l ++) - 1]);
            if (r % 2 == 1) racc = mon.append(a[(-- r) - 1], racc);
        }
        return mon.append(lacc, racc);
    }
};
struct gcd_monoid {
    typedef ll underlying_type;
    ll unit() const { return 0; }
    ll append(ll a, ll b) const { return a and b ? __gcd(a, b) : a ? a : b; }
};

template <class OperatorMonoid>
struct dual_segment_tree {
    typedef typename OperatorMonoid::underlying_type operator_type;
    typedef typename OperatorMonoid::target_type underlying_type;
    int n;
    vector<operator_type> f;
    vector<underlying_type> a;
    const OperatorMonoid op;
    dual_segment_tree() = default;
    dual_segment_tree(int a_n, underlying_type initial_value, OperatorMonoid const & a_op = OperatorMonoid()) : op(a_op) {
        n = 1; while (n < a_n) n *= 2;
        a.resize(n, initial_value);
        f.resize(n - 1, op.unit());
    }
    underlying_type point_get(int i) { // 0-based
        underlying_type acc = a[i];
        for (i = (i + n) / 2; i > 0; i /= 2) { // 1-based
            acc = op.apply(f[i - 1], acc);
        }
        return acc;
    }
    void range_apply(int l, int r, operator_type z) { // 0-based, [l, r)
        assert (0 <= l and l <= r and r <= n);
        range_apply(0, 0, n, l, r, z);
    }
    void range_apply(int i, int il, int ir, int l, int r, operator_type z) {
        if (l <= il and ir <= r) { // 0-based
            if (i < f.size()) {
                f[i] = op.append(z, f[i]);
            } else {
                a[i - n + 1] = op.apply(z, a[i - n + 1]);
            }
        } else if (ir <= l or r <= il) {
            // nop
        } else {
            range_apply(2 * i + 1, il, (il + ir) / 2, 0, n, f[i]);
            range_apply(2 * i + 2, (il + ir) / 2, ir, 0, n, f[i]);
            f[i] = op.unit();
            range_apply(2 * i + 1, il, (il + ir) / 2, l, r, z);
            range_apply(2 * i + 2, (il + ir) / 2, ir, l, r, z);
        }
    }
};
struct plus_operator_monoid {
    typedef ll underlying_type;
    typedef ll target_type;
    ll unit() const { return 0; }
    ll append(ll a, ll b) const { return a + b; }
    ll apply(ll a, ll b) const { return a + b; }
};

int main() {
    // init
    int n; cin >> n;
    dual_segment_tree<plus_operator_monoid> a(n, 0);
    REP (i, n) {
        int a_i; cin >> a_i;
        a.range_apply(i, i + 1, a_i);
    }

    segment_tree<gcd_monoid> delta(n - 1);
    REP (i, n - 1) {
        delta.point_set(i, abs(a.point_get(i + 1) - a.point_get(i)));
    }

    // query
    int m; cin >> m;
    while (m --) {
        int t, l, r; cin >> t >> l >> r;
        -- l;
        if (t) {
            a.range_apply(l, r, t);
            if (l > 0) delta.point_set(l - 1, abs(a.point_get(l) - a.point_get(l - 1)));
            if (r < n) delta.point_set(r - 1, abs(a.point_get(r) - a.point_get(r - 1)));

        } else {
            int d = a.point_get(l);
            if (r - l >= 2) {
                d = __gcd(d, (int)delta.range_concat(l, r - 1));
            }
            cout << d << endl;
        }
    }
    return 0;
}
```

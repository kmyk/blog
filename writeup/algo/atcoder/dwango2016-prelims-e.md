---
layout: post
redirect_from:
  - /writeup/algo/atcoder/dwango2016-prelims-e/
  - /blog/2018/03/02/dwango2016-prelims-e/
date: "2018-03-02T17:24:24+09:00"
tags: [ "competitive", "writeup", "atcoder", "dwacon", "segment-tree", "dp", "inline-dp", "lazy-propagation", "binary-search" ]
"target_url": [ "https://beta.atcoder.jp/contests/dwango2016-prelims/tasks/dwango2016qual_e" ]
---

# 第2回 ドワンゴからの挑戦状 予選: E - 花火

## solution

凸性を使って実家DP。$O(N (\log L)^2)$。

まず$O(NL)$愚直DPから。
同時に複数の花火が上がることはないと仮定して $\mathrm{dp}(i + 1, x) = \min \\{ \mathrm{dp}(i, y) \mid y \le x \\} + \|x - p\_i\|$ と書ける。
同時に複数の花火が上がる場合への修正は容易だが、特にこれを二段階に分けると次に繋がりやすい。
つまり以下のふたつに分ける:

1.  時刻が進んだとき $\mathrm{dp}(x) \gets \min \\{ \mathrm{dp}(y) \mid y \le x \\}$ と更新
2.  花火が打ち上がったとき $\mathrm{dp}(x) \gets \mathrm{dp}(x) + \|x - p\_i\|$ と更新

これを高速に処理したい。
1. は容易だとしても 2. が難しい。
そこで常に$\mathrm{dp}(x)$が下に凸の形をしていることを使う。
三分探索などで最小値を得て、その点より右を全て最小値で埋めればよい。
これは区間更新/点取得の遅延伝播segment木を用いれば可能。
区間取得の不在により作用の満たすべき要件が緩いため、一般的な形で書くと次が乗せられる:

-   区間に座標$x$の多項式$f(x)$を足し込む
-   区間を全て$0$で初期化

これで$O(N (\log L)^2)$。

## note

遅延伝播segment木という言葉が暗に区間更新/区間和であることを指して使われることが多い気がするけど、遅延伝播だが区間更新/区間和*ではない*segment木の強さを考えると、「遅延伝播」「区間更新/区間和」の区別は陽に付けた方が正しい気がする。
となるとライブラリでは区間更新/区間和に `lazy_propagation_segment_tree` って付けたから区間更新/点取得は `dual_segment_tree` にしたけど正しくない気がして変えたくなってきた。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using ll = long long;
using namespace std;

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
        f.resize(n-1, op.unit());
    }
    underlying_type point_get(int i) { // 0-based
        underlying_type acc = a[i];
        for (i = (i+n)/2; i > 0; i /= 2) { // 1-based
            acc = op.apply(f[i-1], acc);
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
                a[i-n+1] = op.apply(z, a[i-n+1]);
            }
        } else if (ir <= l or r <= il) {
            // nop
        } else {
            range_apply(2*i+1, il, (il+ir)/2, 0, n, f[i]);
            range_apply(2*i+2, (il+ir)/2, ir, 0, n, f[i]);
            f[i] = op.unit();
            range_apply(2*i+1, il, (il+ir)/2, l, r, z);
            range_apply(2*i+2, (il+ir)/2, ir, l, r, z);
        }
    }
};
struct grad_init_operator_monoid {
    typedef tuple<ll, ll, bool, int> underlying_type;  // (a, b, does_erase, set_index), add a * index + b
    typedef pair<ll, int> target_type;  // (value, index)
    underlying_type unit() const {
        return make_tuple(0ll, 0ll, false, -1);
    }
    underlying_type append(underlying_type f, underlying_type g) const {
        if (get<2>(f)) return f;
        ll a = get<0>(f) + get<0>(g);
        ll b = get<1>(f) + get<1>(g);
        bool does_erase = get<2>(g);
        int set_index = max(get<3>(f), get<3>(g));
        return make_tuple(a, b, does_erase, set_index);
    }
    target_type apply(underlying_type f, target_type x) const {
        ll a, b; bool does_erase; int set_index; tie(a, b, does_erase, set_index) = f;
        ll value; int index; tie(value, index) = x;
        ll next_value = a * index + b + (does_erase ? 0 : value);
        int next_index = set_index != -1 ? set_index : index;
        return make_pair(next_value, next_index);
    }
};

template <typename UnaryPredicate>
int64_t binsearch(int64_t l, int64_t r, UnaryPredicate p) {
    assert (l <= r);
    -- l;
    while (r - l > 1) {
        int64_t m = l + (r - l) / 2;  // avoid overflow
        (p(m) ? r : l) = m;
    }
    return r;
}

int main() {
    // input
    int n, l; scanf("%d%d", &n, &l);
    vector<int> t(n), p(n);
    REP (i, n) scanf("%d%d", &t[i], &p[i]);

    // solve
    // // reverse poss to ignore times
    for (int l = 0; l < n; ) {
        int r = l;
        while (r < n and t[l] == t[r]) ++ r;
        reverse(p.begin() + l, p.begin() + r);
        l = r;
    }
    // // compute dp
    dual_segment_tree<grad_init_operator_monoid> dp(l + 1, make_pair(0, -1));
    REP (x, l + 1) {
        dp.range_apply(x, x + 1, make_tuple(0ll, 0ll, false, x));  // init
    }
    for (int p_i : p) {
        dp.range_apply(0, p_i, make_tuple(-1, p_i, false, -1));
        dp.range_apply(p_i, l + 1, make_tuple(1, - p_i, false, -1));
        int x = binsearch(0, l, [&](int x) {
            return dp.point_get(x + 1).first - dp.point_get(x).first >= 0;
        });
        ll min_dp = dp.point_get(x).first;
        dp.range_apply(x, l + 1, make_tuple(0ll, min_dp, true, -1));
    }

    // output
    ll result = dp.point_get(l).first;
    printf("%lld\n", result);
    return 0;
}
```

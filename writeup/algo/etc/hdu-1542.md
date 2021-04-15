---
redirect_from:
  - /writeup/algo/etc/hdu-1542/
layout: post
date: 2018-11-03T16:32:56+09:00
tags: [ "competitive", "writeup", "hangzhou-dianzi-university", "segment-tree", "partiality-extension", "speepline", "lazy-propagation", "imos-method", "coordinate-compression" ]
"target_url": [ "http://acm.hdu.edu.cn/showproblem.php?pid=1542", "https://cn.vjudge.net/problem/HDU-1542" ]
---

# HDU - 1542: Atlantis

## 解法

### 概要

#### $$O(n^2 \log n)$$

座標圧縮して通常の遅延伝搬segment木などでsweepline

#### $$O(n^2)$$

座標圧縮してimos法

#### $$O(n \log n)$$

座標圧縮して部分性拡張した遅延伝搬segment木 <https://kimiyuki.net/blog/2018/11/03/lazy-propagation-segment-tree/>

## メモ

<https://github.com/kmyk/competitive-programming-library/issues/3>

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define ALL(x) begin(x), end(x)
using namespace std;

template <class Monoid, class OperatorMonoid>
struct lazy_propagation_segment_tree { // on monoids
    static_assert (is_same<typename Monoid::underlying_type, typename OperatorMonoid::target_type>::value, "");
    typedef typename Monoid::underlying_type underlying_type;
    typedef typename OperatorMonoid::underlying_type operator_type;
    const Monoid mon;
    const OperatorMonoid op;
    int n;
    vector<underlying_type> a;
    vector<operator_type> f;
    lazy_propagation_segment_tree() = default;
    lazy_propagation_segment_tree(int a_n, underlying_type initial_value = Monoid().unit(), Monoid const & a_mon = Monoid(), OperatorMonoid const & a_op = OperatorMonoid())
            : mon(a_mon), op(a_op) {
        n = 1; while (n <= a_n) n *= 2;
        a.resize(2 * n - 1, mon.unit());
        fill(a.begin() + (n - 1), a.begin() + ((n - 1) + a_n), initial_value); // set initial values
        REP_R (i, n - 1) a[i] = mon.append(a[2 * i + 1], a[2 * i + 2]); // propagate initial values
        f.resize(max(0, (2 * n - 1) - n), op.identity());
    }
    void point_set(int i, underlying_type z) {
        assert (0 <= i and i < n);
        point_set(0, 0, n, i, z);
    }
    void point_set(int i, int il, int ir, int j, underlying_type z) {
        if (i == n + j - 1) { // 0-based
            a[i] = z;
        } else if (ir <= j or j+1 <= il) {
            // nop
        } else {
            flush(i, il, ir, false);
            point_set(2 * i + 1, il, (il + ir) / 2, j, z);
            point_set(2 * i + 2, (il + ir) / 2, ir, j, z);
            a[i] = mon.append(a[2 * i + 1], a[2 * i + 2]);
        }
    }
    void range_apply(int l, int r, operator_type z) {
        assert (0 <= l and l <= r and r <= n);
        if (z == op.identity()) return;
        range_apply(0, 0, n, l, r, z);
    }
    void range_apply(int i, int il, int ir, int l, int r, operator_type z) {
        if (l <= il and ir <= r) { // 0-based
            if (i < f.size()) f[i] = op.compose(z, f[i]);
            try {
                a[i] = op.apply(z, a[i]);
            } catch (typename OperatorMonoid::domain_error e) {
                if (i < f.size()) {
                    flush(i, il, ir, false);
                    a[i] = mon.append(a[2 * i + 1], a[2 * i + 2]);
                } else {
                    assert (false);
                }
            }
        } else if (ir <= l or r <= il) {
            // nop
        } else {
            flush(i, il, ir, false);
            range_apply(2 * i + 1, il, (il + ir) / 2, l, r, z);
            range_apply(2 * i + 2, (il + ir) / 2, ir, l, r, z);
            a[i] = mon.append(a[2 * i + 1], a[2 * i + 2]);
        }
    }
    underlying_type range_concat(int l, int r) {
        assert (0 <= l and l <= r and r <= n);
        return range_concat(0, 0, n, l, r);
    }
    underlying_type range_concat(int i, int il, int ir, int l, int r) {
        if (l <= il and ir <= r) { // 0-based
            return a[i];
        } else if (ir <= l or r <= il) {
            return mon.unit();
        } else {
            try {
                return op.apply(f[i], mon.append(
                    range_concat(2 * i + 1, il, (il + ir) / 2, l, r),
                    range_concat(2 * i + 2, (il + ir) / 2, ir, l, r)));
            } catch (typename OperatorMonoid::domain_error e) {
                flush(i, il, ir, true);
                return mon.append(
                    range_concat(2 * i + 1, il, (il + ir) / 2, l, r),
                    range_concat(2 * i + 2, (il + ir) / 2, ir, l, r));
            }
        }
    }
private:
    void flush(int i, int il, int ir, bool pred) {
        if (f[i] == op.identity()) return;
        range_apply(2 * i + 1, il, (il + ir) / 2, 0, n, f[i]);
        range_apply(2 * i + 2, (il + ir) / 2, ir, 0, n, f[i]);
        f[i] = op.identity();
        if (pred) a[i] = mon.append(a[2 * i + 1], a[2 * i + 2]);
    }
};

template <typename T>
struct count_monoid_with_range {
    typedef struct {
        T l, r;  // of range
        bool is_atomic;
        int multiplicity;
        T covered;
    } underlying_type;
    underlying_type unit() const {
        return (underlying_type) { -1, -1, false, -1, -1 };
    }
    underlying_type append(underlying_type a, underlying_type b) const {
        if (a.multiplicity == -1) return b;
        if (b.multiplicity == -1) return a;
        underlying_type c;
        c.l = a.l;
        c.r = b.r;
        c.is_atomic = false;
        c.multiplicity = min(a.multiplicity, b.multiplicity);
        c.covered = a.covered + b.covered;
        return c;
    }
};

template <typename T>
struct increment_operator_monoid_with_range {
    typedef int underlying_type;
    typedef typename count_monoid_with_range<T>::underlying_type target_type;
    typedef struct {} domain_error;
    underlying_type identity() const {
        return 0;
    }
    target_type apply(underlying_type a, target_type b) const {
        if (a == 0) return b;
        b.multiplicity += a;
        if (b.multiplicity > 0) {
            b.covered = b.r - b.l;
        } else if (b.is_atomic) {
            b.covered = 0;
        } else {
            throw (domain_error) {};
        }
        return b;
    }
    underlying_type compose(underlying_type a, underlying_type b) const {
        return a + b;
    }
};

double solve(int n, vector<double> const & x1, vector<double> const & y1, vector<double> const & x2, vector<double> const & y2) {
    // coordinate compression
    vector<double> xs;
    xs.insert(xs.end(), ALL(x1));
    xs.insert(xs.end(), ALL(x2));
    sort(ALL(xs));
    xs.erase(unique(ALL(xs)), xs.end());
    auto compress = [&](double x) { return lower_bound(ALL(xs), x) - xs.begin(); };

    // prepare segtree
    lazy_propagation_segment_tree<count_monoid_with_range<double>, increment_operator_monoid_with_range<double> > segtree(xs.size() - 1);
    REP (i, xs.size() - 1) {
        typename count_monoid_with_range<double>::underlying_type a;
        a.l = xs[i];
        a.r = xs[i + 1];
        a.is_atomic = true;
        a.multiplicity = 0;
        a.covered = 0;
        segtree.point_set(i, a);
    }

    // prepare events
    vector<tuple<double, int, int, int> > events;
    REP (i, n) {
        events.emplace_back(y1[i], compress(x1[i]), compress(x2[i]), +1);
        events.emplace_back(y2[i], compress(x1[i]), compress(x2[i]), -1);
    }
    sort(ALL(events));

    // use sweepline
    double acc = 0;
    double last_y = 0;
    for (auto event : events) {
        double y; int l, r, delta; tie(y, l, r, delta) = event;
        acc += (y - last_y) * segtree.range_concat(0, xs.size()).covered;
        segtree.range_apply(l, r, delta);
        last_y = y;
    }

    return acc;
}

int main() {
    for (int testcase = 1; ; ++ testcase) {
        int n; cin >> n;
        if (n == 0) break;
        vector<double> x1(n), y1(n), x2(n), y2(n);
        REP (i, n) {
            cin >> x1[i] >> y1[i] >> x2[i] >> y2[i];
        }
        cout << "Test case #" << testcase << endl;
        cout << "Total explored area: " << fixed << setprecision(2) << solve(n, x1, y1, x2, y2) << endl;
        cout << endl;
    }
    return 0;
}
```

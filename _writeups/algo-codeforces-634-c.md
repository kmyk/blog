---
layout: post
redirect_from:
  - /writeup/algo/codeforces/634-c/
  - /blog/2016/02/29/cf-634-c/
date: 2016-02-29T04:59:51+09:00
tags: [ "competitive", "writeup", "codeforces", "segment-tree", "range-sum-query" ]
---

# 8VC Venture Cup 2016 - Final Round (Div. 1 Edition) C. Factory Repairs

## [C. Factory Repairs](http://codeforces.com/contest/634/problem/C)

range sum queryな問題。

``` c++
#include <iostream>
#include <vector>
#include <functional>
#include <cmath>
typedef long long ll;
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;

template <typename T>
struct segment_tree { // on monoid
    int n;
    vector<T> a;
    function<T (T,T)> append; // associative
    T unit;
    template <typename F>
    segment_tree(int a_n, T a_unit, F a_append) {
        n = pow(2,ceil(log2(a_n)));
        a.resize(2*n-1, a_unit);
        unit = a_unit;
        append = a_append;
    }
    void point_update(int i, T z) {
        a[i+n-1] = z;
        for (i = (i+n)/2; i > 0; i /= 2) {
            a[i-1] = append(a[2*i-1], a[2*i]);
        }
    }
    T range_concat(int l, int r) {
        return range_concat(0, 0, n, l, r);
    }
    T range_concat(int i, int il, int ir, int l, int r) {
        if (l <= il and ir <= r) {
            return a[i];
        } else if (ir <= l or r <= il) {
            return unit;
        } else {
            return append(
                    range_concat(2*i+1, il, (il+ir)/2, l, r),
                    range_concat(2*i+2, (il+ir)/2, ir, l, r));
        }
    }
};

int main() {
    int n, k, a, b, q; cin >> n >> k >> a >> b >> q;
    segment_tree<ll> ta(n, 0, [&](int x, int y) { return x + y; });
    segment_tree<ll> tb(n, 0, [&](int x, int y) { return x + y; });
    repeat (query,q) {
        int type; cin >> type;
        if (type == 1) {
            int d, c; cin >> d >> c; -- d;
            ta.point_update(d, min<ll>(a, ta.range_concat(d, d+1) + c));
            tb.point_update(d, min<ll>(b, tb.range_concat(d, d+1) + c));
        } else if (type == 2) {
            int p; cin >> p; -- p;
            cout << tb.range_concat(0, p) + ta.range_concat(min(p + k, n), n) << endl;
        }
    }
    return 0;
}
```

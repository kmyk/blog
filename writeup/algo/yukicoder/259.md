---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/259/
  - /blog/2016/09/08/yuki-259/
date: "2016-09-08T23:05:28+09:00"
tags: [ "competitive", "writeup", "yukicoder", "segment-tree" ]
"target_url": [ "http://yukicoder.me/problems/no/259" ]
---

# Yukicoder No.259 セグメントフィッシング＋

平衡二分探索木のtagが付いていたので解いたが、普通のsegment木で十分だった。
<http://yukicoder.me/problems/no/151>の続きとなる問題。

## solution

配列を繋いでsegment木。$O(Q\log N)$。

左向きの魚と右向きの魚の操作は循環しているので、長さ$2N$の配列をひとつ持ち、$i+t \bmod 2N$などをindexとして参照すれば、魚の位置を動かす必要がなくなる。
配列のある点への加算、配列のある区間の総和、に帰着するので、これは単にsegment木で済む。

## implementation

総和を取る部分で、添字をそのまま反転すると$(z, y]$のようになってしまうことに注意。


``` c++
#include <iostream>
#include <vector>
#include <functional>
#include <cmath>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;

template <typename T>
struct segment_tree { // on monoid
    int n;
    vector<T> a;
    function<T (T,T)> append; // associative
    T unit; // unit
    segment_tree() = default;
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
    T point_concat(int l) {
        return range_concat(l, l+1);
    }
};

int main() {
    int n, q; cin >> n >> q;
    segment_tree<ll> a(2*n, 0, plus<ll>());
    auto append = [&](int i, int z) {
        a.point_update(i, a.point_concat(i) + z);
    };
    auto concat = [&](int l, int r) {
        return l < r
            ? a.range_concat(l, r)
            : a.range_concat(0, r) + a.range_concat(l, 2*n);
    };
    while (q --) {
        char c; int t, y, z; cin >> c >> t >> y >> z;
        auto r = [&](int i) { return ((    i  -t) % (2*n) + 2*n) % (2*n); };
        auto l = [&](int i) { return ((2*n-i-1-t) % (2*n) + 2*n) % (2*n); };
        switch (c) {
            case 'L':
                append(l(y), z); break;
            case 'R':
                append(r(y), z); break;
            case 'C':
                cout << concat(r(y), r(z)) + concat(l(z-1), l(y-1)) << endl;
                break;
        }
    }
    return 0;
}
```

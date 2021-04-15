---
layout: post
redirect_from:
  - /writeup/algo/atcoder/dwacon-2017-finals-d/
  - /blog/2017/01/17/dwacon-2017-finals-d/
date: "2017-01-17T06:26:30+09:00"
tags: [ "competitive", "writeup", "dwacon", "atcoder", "segment-tree", "lazy-propagation" ]
"target_url": [ "https://beta.atcoder.jp/contests/dwacon2017-honsen/tasks/dwango2017final_d" ]
---

# 第3回 ドワンゴからの挑戦状 本選: D - 「ドワンゴからの挑戦状」製作秘話

## solution

候補を作って検証する。$O(N\log N)$。

クエリ列を逆になめて初期状態の候補を構成する。
$a_l, a\_{l+1}, \dots, a_r$にそれぞれ$x$を足しその後の最大値が$y$であった、というのを逆転させる。
$a_l, a\_{l+1}, \dots, a_r$の最大値が$y$になるように増減させその後それぞれ$x$を引く、になる。
最大値が$y$というのは、全て$y$以下かつちょうど$y$なものがひとつ以上存在するということ。特にちょうど$y$なものの存在性が面倒。
しかし最後に検証をすることにすれば、構成が不可能な場合は無視してよい。
よって、$a_l, a\_{l+1}, \dots, a_r$を$10^{18}$で初期化してから始め、クエリを逆順に処理していく。
まず主に全て$y$以下のみ満たすことを考え、$a_l, a\_{l+1}, \dots, a_r$のそれぞれを$y$との最小値で更新する。
これでちょうど$y$のものができていればそれでよいし、そうでなければそもそも不可能であり問題ない。
その後全体から$x$を引く。
これを繰り返せば候補が構成できる。

区間一様加算/区間$\max$取得や区間一様減算/区間$\min$更新は、共に遅延伝播segment木で扱える。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <tuple>
#include <functional>
#include <cmath>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
using ll = long long;
using namespace std;

template <typename M, typename Q>
struct lazy_propagation_segment_tree { // on monoids
    int n;
    vector<M> a;
    vector<Q> q;
    function<M (M,M)> append_m; // associative
    function<Q (Q,Q)> append_q; // associative, not necessarily commutative
    function<M (Q,M)> apply; // distributive, associative
    M unit_m; // unit
    Q unit_q; // unit
    lazy_propagation_segment_tree() = default;
    lazy_propagation_segment_tree(int a_n, M a_unit_m, Q a_unit_q, function<M (M,M)> a_append_m, function<Q (Q,Q)> a_append_q, function<M (Q,M)> a_apply) {
        n = pow(2,ceil(log2(a_n)));
        a.resize(2*n-1,     a_unit_m);
        // q.resize(2*(n-1)-1, a_unit_q);
        q.resize(2*n-1, a_unit_q);
        unit_m = a_unit_m;
        unit_q = a_unit_q;
        append_m = a_append_m;
        append_q = a_append_q;
        apply = a_apply;
    }
    void range_apply(int l, int r, Q z) {
        range_apply(0, 0, n, l, r, z);
    }
    void range_apply(int i, int il, int ir, int l, int r, Q z) {
        if (l <= il and ir <= r) {
            a[i] = apply(z, a[i]);
            // if (i < q.size()) q[i] = append_q(z, q[i]);
            q[i] = append_q(z, q[i]);
        } else if (ir <= l or r <= il) {
            // nop
        } else {
            range_apply(2*i+1, il, (il+ir)/2, 0, n, q[i]);
            range_apply(2*i+1, il, (il+ir)/2, l, r, z);
            range_apply(2*i+2, (il+ir)/2, ir, 0, n, q[i]);
            range_apply(2*i+2, (il+ir)/2, ir, l, r, z);
            a[i] = append_m(a[2*i+1], a[2*i+2]);
            q[i] = unit_q;
        }
    }
    M range_concat(int l, int r) {
        return range_concat(0, 0, n, l, r);
    }
    M range_concat(int i, int il, int ir, int l, int r) {
        if (l <= il and ir <= r) {
            return a[i];
        } else if (ir <= l or r <= il) {
            return unit_m;
        } else {
            return apply(q[i], append_m(
                    range_concat(2*i+1, il, (il+ir)/2, l, r),
                    range_concat(2*i+2, (il+ir)/2, ir, l, r)));
        }
    }
};

const ll inf = 1e18;
int main() {
    // input
    int n; cin >> n;
    int q; cin >> q;
    vector<int> l(q), r(q), x(q), y(q); repeat (i,q) { cin >> l[i] >> r[i] >> x[i] >> y[i]; -- l[i]; }
    // backward
    lazy_propagation_segment_tree<ll,pair<ll,ll> > segtree_back(n, 0, make_pair(0, inf), [](ll a, ll b) {
        return a + b;
    }, [](pair<ll,ll> p, pair<ll,ll> q) {
        ll x1, y1; tie(x1, y1) = q;
        ll x2, y2; tie(x2, y2) = p;
        return make_pair( x1 + x2, min(y1, y2 + x1) );
    }, [](pair<ll,ll> q, ll a) {
        ll x, y; tie(x, y) = q;
        return min(a, y) - x;
    });
    repeat (i,n) segtree_back.range_apply(i, i+1, make_pair(- inf, 0));
    repeat_reverse (i,q) segtree_back.range_apply(l[i], r[i], make_pair(x[i], y[i]));
    vector<ll> a(n);
    repeat (i,n) a[i] = segtree_back.range_concat(i, i+1);
    // forward
    lazy_propagation_segment_tree<ll,ll> segtree_for(n, - inf, 0, [](ll a, ll b) {
        return max(a, b);
    }, [](ll p, ll q) {
        return p + q;
    }, [](ll q, ll a) {
        return q + a;
    });
    bool is_ok = true;
    repeat (i,n) segtree_for.range_apply(i, i+1, inf + a[i]);
    repeat (i,q) {
        segtree_for.range_apply(l[i], r[i], x[i]);
        if (segtree_for.range_concat(l[i], r[i]) != y[i]) {
            is_ok = false;
            break;
        }
    }
    // output
    if (is_ok) {
        cout << "OK" << endl;
        repeat (i,n) {
            if (i) cout << ' ';
            cout << a[i];
        }
        cout << endl;
    } else {
        cout << "NG" << endl;
    }
    return 0;
}
```

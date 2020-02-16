---
layout: post
redirect_from:
  - /blog/2017/11/26/cf17-final-e/
date: "2017-11-26T10:02:29+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "greedy", "interval", "segment-tree" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf17-final-open/tasks/cf17_final_e" ]
---

# CODE FESTIVAL 2017 Final: E - Combination Lock

editorialに書かれている解法は思い付くのが難しそうなので貪欲がおすすめ。

## solution

ある種の貪欲。両端から順に揃えていく。
$[0, l)$と$[r, \|S\|)$への操作が可能なら$[l, r)$への操作も可能だと見做してよいというのがアイデア。
解析が上手くできないので大きめに取って上界は$O(N + \|S\|^2)$。

操作の誘導について:

-   回文を作る際に影響するのは相対的なものだけなので、$[0, \|S\|)$への操作は可能としてよい。 一般化して$[k, \|S\| - k)$の全てについて可能。
-   $[l, m)$と$[l, r)$への操作が可能なら、$[m, r)$への操作も可能。$l, r$の逆も同じ。
-   $[0, l)$と$[r, \|S\|)$への操作が可能なら、$[l, r)$への操作も可能となる。一般化して$[k, l), [r, \|S\| - k)$でも。

これを踏まえて両端から順に揃えていく。
$S\_0, S\_{\|S\| - 1}$を変化させられる操作は$[0, r), [l, \|S\|)$の形なのでひとまずこれだけ考えればよい。
誘導された操作を使えば、$S\_0, S\_{\|S\| - 1}$を一致させるためにどのように操作を選んでも後に影響しないことが言える。
つまり、何でもよいので$S\_0, S\_{\|S\| - 1}$を揃え、誘導される操作を全て列挙し、$[0, r), [l, \|S\|)$の形のものについては全て忘れてしまえばよい。
これを再帰的に繰り返して途中で失敗するかを見れば終わり。

実装の注意として:
誘導される操作の列挙は対$(l, r)$として辞書順で整列し隣接するものについていい感じにする。
区間に$+1$したくなるのでsegment木を使う。

## implementation

``` c++
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <iostream>
#include <tuple>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(x) begin(x), end(x)
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }

template <class OperatorMonoid>
struct dual_segment_tree {
    typedef OperatorMonoid monoid_type;
    typedef typename OperatorMonoid::underlying_type operator_type;
    typedef typename OperatorMonoid::target_type underlying_type;
    int n;
    vector<operator_type> f;
    vector<underlying_type> a;
    OperatorMonoid op;
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
template <int mod>
struct modplus_operator_t {
    typedef int underlying_type;
    typedef int target_type;
    int unit() const { return 0; }
    int append(int a, int b) const { return (a + b) % mod; }
    int apply(int a, int b) const { return (a + b) % mod; }
};

bool solve(string s, vector<pair<int, int> > const & lrs) {
    int n = s.length();
    dual_segment_tree<modplus_operator_t<26> > segtree(n, 0);
    repeat (i, n) {
        segtree.range_apply(i, i + 1, s[i] - 'a');
    }
    vector<vector<pair<int, int> > > xlrs(n / 2 + 3);
    auto push = [&](int l, int r) {
        assert (0 <= l and l <= r and r <= n);
        if (l == r) return;
        xlrs[min(l, n - r)].emplace_back(l, r);
    };
    for (auto lr : lrs) {
        int l, r; tie(l, r) = lr;
        push(l, r);
    }
    repeat (k, n / 2) {
        int l = k, r = n - k;
        bool complemented = count(whole(xlrs[k]), make_pair(l, r));
        if (complemented) {
            xlrs[k].erase(remove(whole(xlrs[k]), make_pair(l, r)), xlrs[k].end());
            int n = xlrs[k].size();
            repeat (i, n) {
                int l1, r1; tie(l1, r1) = xlrs[k][i];
                if (l == l1) xlrs[k].emplace_back(r1, r);
                if (r == r1) xlrs[k].emplace_back(l, l1);
            }
        }
        sort(whole(xlrs[k]));
        xlrs[k].erase(unique(whole(xlrs[k])), xlrs[k].end());
        if (xlrs[k].empty()) {
            if (segtree.point_get(l) != segtree.point_get(r - 1)) return false;
            continue;
        }
        repeat (i, xlrs[k].size() - 1) {
            int l1, r1; tie(l1, r1) = xlrs[k][i];
            int l2, r2; tie(l2, r2) = xlrs[k][i + 1];
            if (l == l1 and l == l2) push(r1, r2);
            if (r == r1 and r == r2) push(l1, l2);
            if (l == l1 and r == r2 and l2 < r1) push(l2, r1);
        }
        int lm = r, rm = l;
        for (auto lr : xlrs[k]) {
            int l1, r1; tie(l1, r1) = lr;
            if (l == l1) setmin(lm, r1);
            if (r == r1) setmax(rm, l1);
        }
        if (lm == r) {
            segtree.range_apply(rm, r, (segtree.point_get(l) - segtree.point_get(r - 1) + 26) % 26);
        } else {
            segtree.range_apply(l, lm, (segtree.point_get(r - 1) - segtree.point_get(l) + 26) % 26);
        }
        if (l < lm and lm < rm and rm < r) {
            push(lm, rm);
        }
    }
    return true;
}

int main() {
    string s; int n; cin >> s >> n;
    vector<pair<int, int> > lrs(n);
    repeat (i, n) {
        int l, r; cin >> l >> r; -- l;
        lrs[i] = { l, r };
    }
    bool result = solve(s, lrs);
    cout << (result ? "YES" : "NO") << endl;
    return 0;
}
```

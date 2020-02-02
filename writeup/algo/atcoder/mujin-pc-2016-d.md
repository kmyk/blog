---
layout: post
alias: "/blog/2016/02/27/mujin-pc-2016-d/"
title: "MUJIN プログラミングチャレンジ  D - 括弧列 / Parenthesis Sequence"
date: 2016-02-27T23:48:25+09:00
tags: [ "competitive", "writeup", "atcoder", "mujin-pc", "segment-tree", "cumulative-sum", "range-minimum-query" ]
---

時間かければ解ける問題なのだが、これを開いた時点で残り30分を切っていたのでだめだった。賞金貰えず。
いつかのicpc asia予選も似た感じの問題がでて似た状況で解けなかったような記憶がある。

## [D - 括弧列 / Parenthesis Sequence](https://beta.atcoder.jp/contests/mujin-pc-2016/tasks/mujin_pc_2016_d)

### 解法

累積和とsegment木で上手くやる。$O(N \log N)$。

`(`と`)`からなる文字列がバランスしているとは、`(`を$+1$で`)`を$-1$で置き換えて累積和を取ると負の項がなくかつ右端が零であるということ。
問題であるのは合計と最小値だけであるので、`?`を`(`と`)`に変えるとすると、ある点を境に左は全て`(`で右は全て`)`であることは明らか。
`?`を`(`と`)`にそれぞれいくつ変えるべきかは簡単に求まり、`?`を一様に置き変えた場合の様子は事前の累積和で高速に求まり、それが負の項を含むかどうかはsegment木で求まる。

### 実装

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <functional>
#include <climits>
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
    int n; string s; cin >> n >> s;
    vector<vector<int> > acc(3, vector<int>(n+1));
    repeat (i,n) acc[0][i+1] = acc[0][i] + (s[i] == ')' ? -1 : 1); // ? -> (
    repeat (i,n) acc[1][i+1] = acc[1][i] + (s[i] == '(' ? 1 : -1); // ? -> )
    repeat (i,n) acc[2][i+1] = acc[2][i] + (s[i] == '(' ? 1 : s[i] == ')' ? -1 : 0); // ? -> ""
    vector<int> cnt(n+1);
    repeat (i,n) cnt[i+1] = cnt[i] + (s[i] == '?');
    vector<segment_tree<int> > minq(2, segment_tree<int>(n+1, INT_MAX, [&](int a, int b) { return min(a,b); }));
    repeat (i,n+1) minq[0].point_update(i, acc[0][i]);
    repeat (i,n+1) minq[1].point_update(i, acc[1][i]);
    int q; cin >> q;
    repeat (query,q) {
        int l, r; cin >> l >> r; -- l;
        bool ans = false;
        if ((r - l) % 2 == 0) {
            int x = acc[2][r] - acc[2][l];
            int y = cnt[r] - cnt[l];
            int z = abs(x) + (y - abs(x)) / 2;
            if (x > 0) z = y - z;
            auto it = lower_bound(cnt.begin() + l, cnt.begin() + r, cnt[l] + z);
            if (it != cnt.end()) {
                int m = it - cnt.begin();
                int op = acc[0][m] - acc[0][l];
                int cl = acc[1][r] - acc[1][m];
                if (op + cl == 0 and minq[0].range_concat(l, m) >= acc[0][l] and minq[1].range_concat(m, r) >= acc[1][r]) {
                    ans = true;
                }
            }
        }
        cout << (ans ? "Yes" : "No") << endl;
    }
    return 0;
}
```

---
layout: post
redirect_from:
  - /writeup/algo/aoj/2644/
  - /blog/2016/01/30/aoj-2644/
date: 2016-01-30T15:38:31+09:00
tags: [ "competitive", "writeup", "aoj", "suffix-array", "segment-tree" ]
---

# AOJ 2644 Longest Match

別の問題の部分問題を解くlibraryのverifyとして解いた。

## [Longest Match](http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=2644)

### 解説

suffix array + segment tree。

suffix arrayを用いれば、ある文字列$t$から始まる$s$の部分文字列の全体を、suffix array上の区間として$O(\|t\| \log \|s\|)$で取得できる。

後は、文字列$x$から始まる$s$の部分文字列の全体の中で最も左から始まるもの、
文字列$y$から始まる$s$の部分文字列の全体の中で最も右から始まるもの、が分かればよい。
これはsuffix array上のrange minimum queryおよびrange maximum queryであるので、単純なsegment treeで処理できる。

### 実装

segment treeは任意のmonoidで動く汎用なやつ。端の処理を丁寧にやれば半群に対応できるはず。

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;

vector<int> suffix_array(string const & s) { // O(nloglogn)
    int n = s.length();
    vector<int> sa(n+1);
    vector<int> rank(n+1);
    repeat (i,n+1) {
        sa[i] = i;
        rank[i] = i < n ? s[i] : -1;
    }
    for (int k = 1; k <= n; k *= 2) {
        auto compare = [&](int i, int j) {
            int ri = i + k <= n ? rank[i + k] : -1;
            int rj = j + k <= n ? rank[j + k] : -1;
            return make_pair(rank[i], ri) < make_pair(rank[j], rj);
        };
        sort(sa.begin(), sa.end(), compare);
        vector<int> dp(n+1);
        dp[sa[0]] = 0;
        repeat (i,n) dp[sa[i+1]] = dp[sa[i]] + compare(sa[i], sa[i+1]);
        rank = dp;
    }
    return sa;
}
int lower_bound(string const & s, vector<int> const & sa, string const & t) { // returns an index on suffix array
    int n = s.size();
    int l = 0, r = n+1;
    while (l + 1 < r) {
        int m = (l + r) / 2;
        (s.compare(sa[m], string::npos, t) < 0 ? l : r) = m;
    }
    return r;
}
int prefix_upper_bound(string const & s, vector<int> const & sa, string const & t) { // returns an index on suffix array
    int n = s.size();
    int l = 0, r = n+1;
    while (l + 1 < r) {
        int m = (l + r) / 2;
        (s.compare(sa[m], t.size(), t) <= 0 ? l : r) = m;
    }
    return r;
}

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
    string s; cin >> s;
    int n = s.size();
    vector<int> sa = suffix_array(s);
    segment_tree<int> xt(n+1, n+2, [](int a, int b) { return min(a,b); });
    segment_tree<int> yt(n+1,   0, [](int a, int b) { return max(a,b); });
    repeat (i,n+1) {
        xt.point_update(i, sa[i]);
        yt.point_update(i, sa[i]);
    }
    int m; cin >> m;
    repeat (i,m) {
        string x, y; cin >> x >> y;
        int xl = lower_bound(s, sa, x);
        int yl = lower_bound(s, sa, y);
        int xr = prefix_upper_bound(s, sa, x);
        int yr = prefix_upper_bound(s, sa, y);
        int l = xt.range_concat(xl, xr);
        int r = yt.range_concat(yl, yr);
        int ans = 0;
        if (xl < xr and yl < yr and l <= r and l + x.length() <= r + y.length()) {
            ans = max(ans, r + int(y.size()) - l);
        }
        cout << ans << endl;
    }
    return 0;
}
```

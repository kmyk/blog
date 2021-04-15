---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/515/
  - /blog/2017/05/09/yuki-515/
date: "2017-05-09T23:28:13+09:00"
tags: [ "competitive", "writeup", "yukicoder", "lcp", "sparse-table" ]
"target_url": [ "http://yukicoder.me/problems/no/515" ]
---

# Yukicoder No.515 典型LCP

## solution

クエリの生成方式に依らず問題は解ける。文字列を整列した上で隣接する同士でLCPを愚直に求め、そうしてできる列の上の$\min$による区間和を求める。
ここでsparse tableを使えば全体で$O(\sum\_i \|s_i\| + N \log N + M)$。

## implementation

以前書いたsparse tableを整形してlibraryとして収録した。

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;

template <class Monoid>
struct sparse_table {
    typedef typename Monoid::type T;
    vector<vector<T> > table;
    Monoid mon;
    sparse_table(vector<T> const & init, Monoid const & a_mon = Monoid())
            : mon(a_mon) {
        int n = init.size();
        int log_n = sqrt(n) + 1;
        table.resize(log_n, vector<T>(n, mon.unit));
        table[0] = init;
        for (int k = 0; k < log_n-1; ++ k) {
            for (int i = 0; i < n; ++ i) {
                table[k+1][i] = mon.append(table[k][i], i + (1ll<<k) < n ? table[k][i + (1ll<<k)] : mon.unit);
            }
        }
    }
    T operator () (int l, int r) {
        assert (0 <= l and l <= r and r <= table[0].size());
        if (l == r) return mon.unit;
        int k = log2(r - l);
        return mon.append(table[k][l], table[k][r - (1ll<<k)]);
    }
};
struct min_t {
    typedef int type;
    const int unit = 1e9+7;
    int append(int a, int b) { return min(a, b); }
};

int compute_lcp(string const & a, string const & b) {
    int i = 0;
    while (i < a.length() and i < b.length() and a[i] == b[i]) ++ i;
    return i;
}

int main() {
    // input
    int n; cin >> n;
    vector<string> s(n); repeat (i,n) cin >> s[i];
    int m; ll x, d; cin >> m >> x >> d;
    // generate queries
    vector<int> qi(m);
    vector<int> qj(m);
    repeat (k,m) {
        qi[k] = x / (n - 1);
        qj[k] = x % (n - 1);
        if (qi[k] > qj[k]) {
            swap(qi[k], qj[k]);
        } else {
            qj[k] += 1;
        }
        x = (x + d) % (n *(ll) (n - 1));
    }
    // construct a sparse table
    vector<int> rank(n);
    whole(iota, rank, 0);
    whole(sort, rank, [&](int i, int j) { return s[i] < s[j]; });
    vector<int> lcp_0(n-1);
    repeat (i,n-1) lcp_0[i] = compute_lcp(s[rank[i]], s[rank[i+1]]);
    sparse_table<min_t> table(lcp_0);
    vector<int> rank_of(n);
    repeat (i,n) rank_of[rank[i]] = i;
    // compute
    ll result = 0;
    repeat (q,m) {
        int l = rank_of[qi[q]];
        int r = rank_of[qj[q]];
        if (l > r) swap(l, r);
        result += table(l, r);
    }
    // output
    cout << result << endl;
    return 0;
}
```

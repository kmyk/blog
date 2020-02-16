---
layout: post
redirect_from:
  - /blog/2017/01/22/fhc-2017-round2-c/
date: "2017-01-22T07:00:10+09:00"
tags: [ "competitive", "writeup", "facebook-hacker-cup", "segment-tree" ]
"target_url": [ "https://www.facebook.com/hackercup/problem/1726375930948061/" ]
---

# Facebook Hacker Cup 2017 Round 2: C - Fighting all the Zombies

間に合わず。

## problem

$N + N$個の頂点からなる$2$部グラフを考える。
$2$つの集合を左側右側とし、それぞれの側の頂点に$0, 1, \dots, N-1$番と番号を付けておく。
初期状態では$i$番の対応する左右の頂点の間に辺がそれぞれ$1$本張られている。
以下のクエリを処理せよ。

-   $i, j, s$が与えられる。$\|i - j\| \le 1$である。左の$i$番目の頂点と右の$j$番目の頂点の間に辺を$s$本張って更新し、その後の最大$2$部マッチングの個数を答えよ。

## solution

segment木。長さ$1$の区間には注意。$O(M \log N)$。

頂点を並べて区間ごとに計算し合成していく。
$i$番目と辺があるのは$i-1, i, i+1$番目だけなので、$i$番目から$i+1$番目への辺を使えば必ず$i+1$番目から$i$番目への辺も使われる。これにより、区間の両端での辺の使い方だけ持てば計算できる。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <functional>
#include <cmath>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;

template <typename T>
struct segment_tree { // on monoid
    int n;
    vector<T> a;
    function<T (T,T)> append; // associative
    T unit; // unit
    segment_tree() = default;
    segment_tree(int a_n, T a_unit, function<T (T,T)> a_append) {
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

const int mod = 1e9+7;
struct spell_t {
    int down, eql, up;
};
struct range_t {
    int length;
    spell_t l, r;
    int dp[2][2]; // { EQL, UP } x { EQL, DOWN }
};
range_t unit() {
    range_t a = {};
    return a;
}
range_t append(range_t const & a, range_t const & b) {
    if (a.length == 0) return b;
    if (b.length == 0) return a;
    range_t c = {};
    c.length = a.length + b.length;
    c.l = a.l;
    c.r = b.r;
    if (a.length == 1 and b.length == 1) {
        c.dp[0][0] = 1;
        c.dp[1][1] = 1;
        c.r = b.l;
    } else if (a.length == 1) {
        assert (false);
    } else if (b.length == 1) {
        repeat (x,2) {
            ll acc = 0;
            acc += a.dp[x][0] *(ll) a.r.eql  % mod;
            acc += a.dp[x][1] *(ll) a.r.down % mod;
            c.dp[x][0] = acc % mod;
        }
        repeat (x,2) {
            c.dp[x][1] = a.dp[x][0] *(ll) a.r.up % mod;
        }
        c.r = b.l;
    } else {
        repeat (x,2) repeat (y,2) {
            ll acc = 0;
            acc += a.dp[x][0] *(ll) a.r.eql  % mod * b.l.eql  % mod * b.dp[0][y] % mod;
            acc += a.dp[x][0] *(ll) a.r.eql  % mod * b.l.up   % mod * b.dp[1][y] % mod;
            acc += a.dp[x][1] *(ll) a.r.down % mod * b.l.eql  % mod * b.dp[0][y] % mod;
            acc += a.dp[x][1] *(ll) a.r.down % mod * b.l.up   % mod * b.dp[1][y] % mod;
            acc += a.dp[x][0] *(ll) a.r.up   % mod * b.l.down % mod * b.dp[0][y] % mod;
            c.dp[x][y] = acc % mod;
        }
    }
    return c;
}

int solve(int n, int m, vector<int> const & w, vector<int> const & z, vector<int> const & s) {
    int result = 0;
    if (n == 1) {
        int acc = 1;
        repeat (i,m) {
            acc = (acc + s[i]) % mod;
            result = (result + acc) % mod;
        }
    } else {
        segment_tree<range_t> segtree(n, unit(), append);
        vector<spell_t> spell(n); // spell : wand x { DOWN, EQL, UP } -> number
        auto update = [&](int i) {
            range_t a = {};
            a.length = 1;
            a.l = spell[i];
            a.r = { 0, 1, 0 };
            a.dp[0][0] = 1;
            segtree.point_update(i, a);
        };
        repeat (i,n) {
            spell[i] = { 0, 1, 0 };
            update(i);
        }
        repeat (i,m) {
            int j = w[i] - 1;
            int d = z[i] - w[i] + 1;
            int *it;
            switch (d) {
                case 0: it = &spell[j].down; break;
                case 1: it = &spell[j].eql;  break;
                case 2: it = &spell[j].up;   break;
            }
            *it = (*it + s[i]) % mod;
            update(j);
            range_t a = segtree.range_concat(0, n);
            ll acc = 0;
            acc += a.l.eql *(ll) a.dp[0][0] % mod * a.r.eql  % mod;
            acc += a.l.eql *(ll) a.dp[0][1] % mod * a.r.down % mod;
            acc += a.l.up  *(ll) a.dp[1][0] % mod * a.r.eql  % mod;
            acc += a.l.up  *(ll) a.dp[1][1] % mod * a.r.down % mod;
            result = (result + acc) % mod;
        }
    }
    return result;
}
int main() {
    int t; cin >> t;
    repeat (i,t) {
        int n, m; cin >> n >> m;
        vector<int> w(m), d(m), s(m);
        int aw, bw; cin >> w[0] >> aw >> bw;
        int ad, bd; cin >> d[0] >> ad >> bd;
        int as, bs; cin >> s[0] >> as >> bs;
        repeat (i,m-1) {
            w[i+1] = (w[i] *(ll) aw + bw) % n + 1;
            d[i+1] = (d[i] *(ll) ad + bd) % 3;
            s[i+1] = (s[i] *(ll) as + bs) % int(1e9) + 1;
        }
        vector<int> z(m);
        repeat (i,m) z[i] = max(1, min(n, w[i] + d[i] - 1));
        cout << "Case #" << i+1 << ": " << solve(n, m, w, z, s) << endl;
    }
    return 0;
}
```

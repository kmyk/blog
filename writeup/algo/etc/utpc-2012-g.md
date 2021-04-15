---
layout: post
redirect_from:
  - /writeup/algo/etc/utpc-2012-g/
  - /blog/2018/01/01/utpc-2012-g/
date: "2018-01-01T10:51:15+09:00"
tags: [ "competitive", "writeup", "utpc", "atcoder", "dp", "combinatorics", "string" ]
"target_url": [ "https://beta.atcoder.jp/contests/utpc2012/tasks/utpc2012_07" ]
---

# 東京大学プログラミングコンテスト2012: G - k番目の文字列

## 反省

部分文字列でなくて部分列だと誤読。
「ただし，アリスは夢を見ていて，このような並べ方は本当は存在しないかもしれない． その場合には，0を答えよ．」とあるが、これを$-1$と誤読。
そもそもまったく分からない。部分点をちゃんと見てれば思い付けていたのだろうか。

## solution

DP。$s$の位置$\mathrm{offset} \le n$を固定し前から$i \le n$文字目まで固定して$s\_0$より小さい数を$j \le$個使って$s$より小さい部分文字列の数が$l \le k \le n^2$個確定しているような状態の数を$\mathrm{dp}(\mathrm{offset}, i, j, l)$とおく。$O(n^5)$。
遷移の肝は、位置$i$に文字$c \lt s\_0$があればこの$c$を先頭とする$n - i$個の部分文字列は$s$より小さいことが確定し、$c \gt s\_0$であればこの数は$0$であること。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define REP3R(i, m, n) for (int i = int(n) - 1; (i) >= int(m); -- (i))
using ll = long long;
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

template <int MOD>
int fact(int n) {
    static vector<int> memo(1, 1);
    while (n >= memo.size()) {
        memo.push_back(memo.back() *(ll) memo.size() % MOD);
    }
    return memo[n];
}

constexpr ll mod = 1000000007;
int main() {
    // input
    int n, k; cin >> n >> k;
    string s; cin >> s;
    // solve
    int lower = 0;
    REP3 (c, 'a', s[0]) {
        lower += (s.find(c) == string::npos);
    }
    ll result = 0;
    REP (offset, n - s.length() + 1) {
        auto cur = vectors(lower + 1, k + 1, -1);
        auto prv = vectors(lower + 1, k + 1, -1);
        cur[0][0] = 1;
        REP (i, n) {
// REP (j, lower + 1) REP (l, k + 1) if (cur[j][l] != -1) fprintf(stderr, "dp[%d][%d][%d][%d] = %d\n", offset, i, j, l, cur[j][l]);
            if (offset <= i and i < offset + s.length()) {
                int delta = -1;
                if (s[i - offset] == s[0]) {
                    delta = s.length();
                } else if (s[i - offset] < s[0]) {
                    delta = n - i;
                }
                if (delta != -1) {
                    delta = min(delta, k + 1);
                    REP (j, lower + 1) {
                        REP3R (l, delta, k + 1) {
                            cur[j][l] = cur[j][l - delta];
                        }
                        REP_R (l, delta) {
                            cur[j][l] = -1;
                        }
                    }
                }
            } else {
                cur.swap(prv);
                REP (j, lower + 1) {
                    REP (l, k + 1) {
                        bool exists = false;
                        ll acc = 0;
                        if (prv[j][l] != -1) {
                            exists = true;
                            acc += prv[j][l];
                        }
                        int pj = j - 1;
                        int pl = l - (n - i);
                        if (pj >= 0 and pl >= 0 and prv[pj][pl] != -1) {
                            exists = true;
                            acc += prv[pj][pl];
                        }
                        cur[j][l] = exists ? acc % mod : -1;
                    }
                }
            }
        }
        if (cur[lower][k] != -1) {
            result += cur[lower][k];
            result %= mod;
        }
// REP (j, lower + 1) REP (l, k + 1) if (cur[j][l] != -1) fprintf(stderr, "dp[%d][%d][%d][%d] = %d\n", offset, n, j, l, cur[j][l]);
    }
    result = result *(ll) fact<mod>(lower) % mod;
    result = result *(ll) fact<mod>(n - lower - s.length()) % mod;
    // output
    printf("%lld\n", result);
    return 0;
}
```

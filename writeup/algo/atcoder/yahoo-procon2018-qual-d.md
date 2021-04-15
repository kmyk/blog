---
layout: post
redirect_from:
  - /writeup/algo/atcoder/yahoo-procon2018-qual-d/
  - /blog/2018/02/14/yahoo-procon2018-qual-d/
date: "2018-02-14T20:15:27+09:00"
tags: [ "competitive", "writeup", "atcoder", "yahoo-procon" ]
"target_url": [ "https://beta.atcoder.jp/contests/yahoo-procon2018-qual/tasks/yahoo_procon2018_qual_d" ]
---

# 「みんなのプロコン 2018」: D - XOR XorY

本番中では間に合わなかったが解説なしで解くのは解けた。

## solution

-   制約は$a\_i \oplus a\_j \oplus A\_{i, j} \in \\{ X, Y \\}$と書ける。これは$A\_{i, j}' = A\_{i, j} \oplus X$と$Y' = Y \oplus X$を考えることで $a\_i \oplus a\_j \oplus A\_{i, j}' \in \{ 0, Y' \}$とできる。つまり$X = 0$と仮定してよい。
-   条件を細かく分けると次の$4$個。これらを全て満たせばよい。
    -   反射性みたいなもの: 対角成分 $A\_{i, i} \in \\{ 0, Y \\}$ でなければならない。
    -   対称性みたいなもの: 対角成分 $A\_{i, j} = A\_{j, i}$ でなければならない。
    -   推移性みたいなもの: $a\_i \oplus a\_j \oplus A\_{i, j} \in \\{ 0, Y \\}$と$a\_j \oplus a\_k \oplus A\_{j, k} \in \\{ 0, Y \\}$が成り立っているとする。このとき $a\_i \oplus a\_k \oplus A\_{i, k} \in \\{ 0, Y \\}$ が常成り立つことが容易に示せる。なので気にしなくてよい。
    -   生成元みたいなもの: $a\_1$は固定されたものとする。任意の$j \ge 2$について$a\_1 \oplus a\_j \oplus A\_{1, j} \in \\{ 0, Y \\}$でなければならない。他は適当にできるので、これだけを考えればよい。
-   $a\_1$について総当たり。$a\_2, \dots, a\_N$が存在しうるかの判定は$x\_\ast$の各元を同値関係 $a \sim b \iff a \oplus b \in \\{ 0, Y \\}$ で割った上でやる。その後 同値関係で割った部分を戻して数え上げる。数え上げ部分は愚直でよい。
-   計算量は$O(N^2)$。



## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

ll powmod(ll x, ll y, ll m) {
    assert (0 <= x and x < m);
    assert (0 <= y);
    ll z = 1;
    for (ll i = 1; i <= y; i <<= 1) {
        if (y & i) z = z * x % m;
        x = x * x % m;
    }
    return z;
}
ll modinv(ll x, ll p) {
    assert (x % p != 0);
    return powmod(x, p - 2, p);
}
template <int32_t MOD>
int32_t fact(int n) {
    static vector<int32_t> memo(1, 1);
    while (n >= memo.size()) {
        memo.push_back(memo.back() *(int64_t) memo.size() % MOD);
    }
    return memo[n];
}
template <int32_t PRIME>
int32_t inv_fact(int n) {
    static vector<int32_t> memo(1, 1);
    while (n >= memo.size()) {
        memo.push_back(memo.back() *(int64_t) modinv(memo.size(), PRIME) % PRIME);
    }
    return memo[n];
}
template <int MOD>
int choose(int n, int r) {
    if (n < r) return 0;
    return fact<MOD>(n) *(ll) inv_fact<MOD>(n - r) % MOD *(ll) inv_fact<MOD>(r) % MOD;
}

constexpr int mod = 1e9 + 7;
int solve(int n, int k, int x, int y, vector<int> & z, vector<vector<int> > & a) {
    // prepare
    sort(ALL(z));
    REP (i, k) REP (j, k) {
        a[i][j] ^= x;
    }
    y ^= x;
    // count
    // the condition: ai ^ aj ^ Aij' \in { 0, Y' }
    REP (i, k) {
        if (a[i][i] != 0 and a[i][i] != y) {
            return 0;
        }
    }
    REP (i, k) REP (j, k) {
        int delta = a[i][j] ^ a[j][i];
        if (delta != 0 and delta != y) {
            return 0;
        }
    }
    map<int, int> freq; for (int z_i : z) freq[min(z_i, z_i ^ y)] += 1;
    map<int, int> merged; for (int z_i : z) if ((z_i ^ y) < z_i) merged[z_i ^ y] += 1;
    ll result = 0;
    for (auto it : freq) {
        vector<int> b(n, -1);
        b[0] = it.first;
        map<int, int> used;
        used[b[0]] += 1;
        REP3 (j, 1, k) {
            int c = a[0][j] ^ b[0];
            c = min(c, c ^ y);
            if (used[c] == freq[c]) {
                goto next;
            }
            used[c] += 1;
        }
        {
            ll acc = 1;
            for (auto it : used) {
                int n = it.second;
                int r1 = freq[it.first] - merged[it.first];
                int r2 = merged[it.first];
                ll acc2 = 0;
                REP (r, n + 1) if (r <= r1 and n - r <= r2) {
                    acc2 += choose<mod>(n, r);
                    acc2 %= mod;
                }
                acc *= acc2;
                acc %= mod;
            }
            result += acc;
            result %= mod;
        }
next: ;
    }
    return result;
}

int main() {
    // input
    int n, k, x, y; cin >> n >> k >> x >> y;
    vector<int> z(n);
    REP (i, n) cin >> z[i];
    auto a = vectors(k, k, int());
    REP (i, k) REP (j, k) cin >> a[i][j];
    // solve
    int result = solve(n, k, x, y, z, a);
    // output
    cout << result << endl;
    return 0;
}
```

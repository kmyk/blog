---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/474/
  - /blog/2016/12/25/yuki-474/
date: "2016-12-25T02:42:18+09:00"
tags: [ "competitive", "writeup", "yukicoder" ]
"target_url": [ "http://yukicoder.me/problems/no/474" ]
---

# Yukicoder No.474 色塗り２

## solution

周期性を使う。$O(\max A_i + T)$。

根付き木に関して。
葉の塗り方は$C$通り。
高さ$2$な部分根付き木の塗り方は$C \cdot {}\_CH_B$通り。
全体の根付き木の塗り方は$C \cdot {}\_{C \cdot {}\_CH_B}H_A$通り。
ただし重複組み合わせ${}\_nH_r = {}\_{n+r-1}C_r$。

$C \cdot {}\_{C \cdot {}\_CH_B}H_A \bmod 2$を求めたい。
`long long`に収まらないような$n$に対し${}\_nC_r \bmod 2$を求めるのは難しいので、$\bmod$に起因する周期性を考えたい。
${}\_nC_r = \frac{n!}{(n-r)!~r!}$であるので、何回$2$で割れるかを求める関数$\mathrm{ctz}$を使って、${}\_nC_r \bmod 2 = 0 \iff \sum\_{i \lt r} (\mathrm{ctz}(n-i) - \mathrm{ctz}(i+1))$である。
$\mathrm{ctz}$の和に落とせた。この関数は高い位置のbitには影響されないので、$M = 2^{\lfloor \log_2 r \rfloor + 1}$として${}\_nC_r = {}\_{n \bmod M}C_r$である。

よって$D = C \cdot {}\_CH_B \bmod M$として$\mathrm{ans} = {}\_{D+A-1 \bmod M}C_A \bmod 2$が答え。
これは階乗への展開を用いて前処理$O( r )$でmemo化しておけば計算できて間に合う。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <tuple>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
typedef long long ll;
using namespace std;
ll powmod(ll x, ll y, ll p) { // O(log y)
    assert (y >= 0);
    x %= p; if (x < 0) x += p;
    ll z = 1;
    for (ll i = 1; i <= y; i <<= 1) {
        if (y & i) z = z * x % p;
        x = x * x % p;
    }
    return z;
}
const int A_MAX = 1000000;
const int MOD   = 1048576; // pow(2, floor(log2(A_MAX)) + 1);
pair<int, int> split(int x) {
    if (x == 0) return make_pair(0, 0);
    int ctz = __builtin_ctz(x);
    return make_pair(x >> ctz, ctz);
}
pair<int, int> inv(pair<int, int> it) {
    int frac, expo; tie(frac, expo) = it;
    assert (frac % 2 == 1);
    static vector<int> memo;
    if (memo.empty()) memo.resize(MOD);
    if (not memo[frac]) {
        memo[frac] = powmod(frac, MOD/2-1, MOD);
        memo[memo[frac]] = frac;
    }
    return make_pair(memo[frac], - expo);
}
pair<int, int> mult(pair<int, int> a, pair<int, int> b) {
    int a_frac, a_expo; tie(a_frac, a_expo) = a;
    int b_frac, b_expo; tie(b_frac, b_expo) = b;
    return make_pair(a_frac *(ll) b_frac % MOD, a_expo + b_expo);
}
int merge(pair<int, int> it) {
    int frac, expo; tie(frac, expo) = it;
    assert (expo >= 0);
    while (expo --) frac = frac * 2 % MOD;
    return frac;
}
pair<int, int> factmod(int n) {
    static vector<pair<int, int> > memo;
    if (memo.empty()) {
        memo.resize(2*MOD);
        memo[0] = { 1, 0 };
        repeat (i,2*MOD-1) memo[i+1] = mult(memo[i], split(i+1));
    }
    return memo[n];
}
int choose_modulo(int n, int r) {
    return merge(mult(factmod(n), inv(mult(factmod(n-r), factmod(r)))));
}
bool solve(int a, int b, int c) {
    assert (a <= A_MAX);
    if (c % 2 == 0) return 0;
    int d = c *(ll) choose_modulo(c+b-1, b) % MOD;
    return choose_modulo(d+a-1, a) % 2;
}
int main() {
    int t; cin >> t;
    while (t --) {
        int a, b, c; cin >> a >> b >> c;
        cout << solve(a, b, c) << endl;
    }
    return 0;
}
```

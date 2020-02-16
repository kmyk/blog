---
layout: post
date: 2018-07-01T23:59:05+09:00
tags: [ "competitive", "writeup", "icpc-domestic", "dp", "matrix", "binary-search", "dp", "exponentiation-by-squaring", "affine-map" ]
"target_url": [ "http://acm-icpc.aitea.net/index.php?2018%2FPractice%2F%E6%A8%A1%E6%93%AC%E5%9B%BD%E5%86%85%E4%BA%88%E9%81%B8%2F%E5%95%8F%E9%A1%8C%E6%96%87%E3%81%A8%E3%83%87%E3%83%BC%E3%82%BF%E3%82%BB%E3%83%83%E3%83%88" ]
---

# ACM-ICPC 2018 模擬国内予選: G. カジノ

## 解法

愚直DPを行列累乗と二分探索で加速。$O(N^4 \log M)$。そこそこ遅い。

まず愚直DPを考えよう。
$6$面ダイスが$N$個というのは偏りのある$5N + 1$面ダイスが$1$個と見ると楽なのでそうする。
現在の出目が$a$で最大$m$回まで振り直してよいときの出目の期待値を$\mathrm{dp}(a, m)$としよう。
漸化式は$\mathrm{dp}(a, m + 1) = \mathrm{max}(a, \sum_b p(b) \mathrm{dp}(b, m))$となる。

なんだか線形感あるので線形にしたい。
ここで$c(m) = \sum_b p(b) \mathrm{dp}(b, m)$は$a$に寄らないため、非線形関数$\mathrm{max}$を展開して$a \ge c(m)$なら$\mathrm{dp}(a, m + 1) = a$かつ$a \le c(m)$なら$\mathrm{dp}(a, m + 1) = c(m)$とできる。
さらに$c(m)$は単調なので、分岐点$a$が変化する回数は高々$5N$回。
どちらの漸化式もAffine写像であるので、vector $x_m = ( \mathrm{dp}(0, m), \mathrm{dp}(1, m), \dots, \mathrm{dp}(5N, m), 1 )$を置けば、各$m$ごとに定まる($5N + 1$種類のうちどれかの)行列$F_m$があって<span>$x_{m + 1} = F_m x_m$</span>。
この行列$F_m$はほぼ変化しないので、変化点を二分探索し、種類ごとにまとめて繰り返し二乗法で計算してやればよい。

## note

解法は出てたが間に合わず

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define REP3R(i, m, n) for (int i = int(n) - 1; (i) >= int(m); -- (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

vector<double> get_dice_probability(int n) {
    int size = 6 * n + 1;
    vector<double> cur(size);
    cur[0] = 1;
    REP (i, n) {
        vector<double> nxt(size);
        REP (a, size) if (cur[a]) {
            REP3 (dice, 1, 6 + 1) {
                nxt[a + dice] += cur[a] / 6;
            }
        }
        cur.swap(nxt);
    }
    return cur;
}

template <typename T>
vector<vector<T> > operator * (vector<vector<T> > const & a, vector<vector<T> > const & b) {
    int n = a.size();
    vector<vector<T> > c = vectors(n, n, T());
    REP (y, n) REP (z, n) REP (x, n) c[y][x] += a[y][z] * b[z][x];
    return c;
}
template <typename T>
vector<T> operator * (vector<vector<T> > const & a, vector<T> const & b) {
    int n = a.size();
    vector<T> c(n);
    REP (y, n) REP (z, n) c[y] += a[y][z] * b[z];
    return c;
}
template <typename T>
vector<vector<T> > unit_matrix(int n) {
    vector<vector<T> > e = vectors(n, n, T());
    REP (i, n) e[i][i] = 1;
    return e;
}
template <typename T>
vector<vector<T> > powmat(vector<vector<T> > x, ll y) {
    int n = x.size();
    auto z = unit_matrix<T>(n);
    for (ll i = 1; i <= y; i <<= 1) {
        if (y & i) z = z * x;
        x = x * x;
    }
    return z;
}

template <typename UnaryPredicate>
int64_t binsearch(int64_t l, int64_t r, UnaryPredicate p) {
    assert (l <= r);
    -- l;
    bool is_first = true;
    while (r - l > 1) {
        int64_t m = l + (r - l) / 2;  // to avoid overflow
        if (is_first) { is_first = false; m = l + 1; }  // ad-hoc heuristics
        (p(m) ? r : l) = m;
    }
    return r;
}

vector<vector<double> > make_ath_matrix(int a, vector<double> const & prob) {
    int size = prob.size();
    auto f = vectors(size + 1, size + 1, double());
    REP (y, size) {
        if (y < a) {
            REP (x, size) {
                f[y][x] = prob[x];
            }
        } else {
            f[y][size] = y;
        }
    }
    f[size][size] = 1;
    return f;
}

double solve(int n, ll m) {
    int size = 6 * n + 1;
    vector<double> prob = get_dice_probability(n);

    vector<double> x(size + 1);
    REP (a, size) x[a] = a;
    x[size] = 1;
    REP (a, size) {
        vector<vector<double> > f = make_ath_matrix(a, prob);
        vector<vector<double> > g = make_ath_matrix(a + 1, prob);
        ll k = binsearch(0, m, [&](ll k) {
            auto y = powmat(f, k) * x;
            return (g * y)[a] >= (f * y)[a];
        });
        x = powmat(f, k) * x;
        m -= k;
cerr << "a = " << a << ", k = " << k << ", x = (";
REP (i, size) cerr << " " << x[i];
cerr << " )" << endl;
        if (m == 0) break;
    }
    vector<vector<double> > f = make_ath_matrix(size, prob);
    x = powmat(f, m) * x;
    return x[0];
}

int main() {
    while (true) {
        int n; ll m; scanf("%d%lld", &n, &m);
        if (n == 0 and m == 0) break;
        printf("%.8lf\n", solve(n, m));
    }
    return 0;
}
```

---
layout: post
date: 2018-08-21T21:33:33+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "matrix", "polynomial", "rolling-hash" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc099/tasks/arc099_d" ]
---

# AtCoder Regular Contest 099: F - Eating Symbols Hard

<!-- {% raw %} -->

## solution

嘘っぽい行列でrolling hashぽくやる。$O(N)$。

文字から操作への対応が与えられていることからなんとなく行列ぽさがある。
長さ $2 \times 10^9 + 1$ の整数列 $A$ と整数 $P$ はまとめて $2 \times 10^9 + 2$ 次元vectorで表せ、問題文中の操作はどれも $2 \times 10^9 + 2$ 次正方行列として表せる。
行列の大きさは後で書く方法で対処できるのでひとまず目をつぶっておく。
用いられる範囲では操作は可逆であるので、行列は正則と見做してよい。
とりあえず操作の行列の積で累積和を取り$A_0, A_1, \dots, A_N$とする。
このとき求めたい答えは $A = A_N$ かつ $x_0$ は初期状態を表現するvectorとして $$ \# \left\{ (l, r) \mid A_r A_l^{-1} x_0 = A x_0 \right\} $$ である。
これは移項すると $$ \# \left\{ (l, r) \mid A_r x_0 = A A_l x_0 \right\} $$ である。
変数$l, r$を左辺右辺それぞれに分離できてかつ等号で比較する形なので、`unordered_map` などでを使って$l$を固定したときの$r$の数がいい感じに求まる。

必要な範囲に絞っても $N \le 2.5 \times 10^5$ 次正方行列ではvectorとの乗算すら難しい。
そこで嘘を入れる。
この議論は多項式として $f = \sum _ {i \in \mathbb{Z}} A _ i x^i$ と表しているのとほぼ同じなのでそのように考える。
台を$\mathbb{Z}$でなく適当な有限体$\mathbb{Z}/p\mathbb{Z}$とし、rolling hashのように適当な素数を代入し$x = q$とする。
すると数列$A$を $a = \sum A _ i q^i \in \mathbb{Z}/p\mathbb{Z}$ と1要素で表わせる。
これで$2 \times 2$の行列を考えればよいこととなる。
ただし$p, q$の組がひとつだけであると衝突が発生するので複数組用意して回避する。

## note

-   方向性は合っていたが、editorialをちら見するまで確信が持てなかった。
-   重要なのは操作なので多項式を基本に説明するのは違う気がする。でも無限次元vectorとかもあまり言いたくない気はする。
-   法がtemplate引数に入る形のライブラリしか用意してなかったので実装が汚い。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
using ll = long long;
using namespace std;

template <int32_t MOD>
struct mint {
    int64_t data;  // faster than int32_t a little
    mint() = default;  // data is not initialized
    mint(int64_t value) : data(value) {}  // assume value is in proper range
    inline mint<MOD> operator + (mint<MOD> other) const { int64_t c = this->data + other.data; return mint<MOD>(c >= MOD ? c - MOD : c); }
    inline mint<MOD> operator - (mint<MOD> other) const { int64_t c = this->data - other.data; return mint<MOD>(c <    0 ? c + MOD : c); }
    inline mint<MOD> operator * (mint<MOD> other) const { int64_t c = this->data * int64_t(other.data) % MOD; return mint<MOD>(c < 0 ? c + MOD : c); }
    inline mint<MOD> & operator += (mint<MOD> other) { this->data += other.data; if (this->data >= MOD) this->data -= MOD; return *this; }
    inline mint<MOD> & operator -= (mint<MOD> other) { this->data -= other.data; if (this->data <    0) this->data += MOD; return *this; }
    inline mint<MOD> & operator *= (mint<MOD> other) { this->data = this->data * int64_t(other.data) % MOD; if (this->data < 0) this->data += MOD; return *this; }
    inline mint<MOD> operator - () const { return mint<MOD>(this->data ? MOD - this->data : 0); }
    mint<MOD> pow(uint64_t k) const {
        mint<MOD> x = *this;
        mint<MOD> y = 1;
        for (uint64_t i = 1; i and (i <= k); i <<= 1) {
            if (k & i) y *= x;
            x *= x;
        }
        return y;
    }
    mint<MOD> inv() const {
        return pow(MOD - 2);
    }
};

template <typename T, size_t H, size_t W>
using matrix = array<array<T, W>, H>;
template <typename T, size_t A, size_t B, size_t C>
matrix<T, A, C> operator * (matrix<T, A, B> const & a, matrix<T, B, C> const & b) {
    matrix<T, A, C> c = {};
    REP (y, A) REP (z, B) REP (x, C) c[y][x] += a[y][z] * b[z][x];
    return c;
}
template <typename T, size_t H, size_t W>
array<T, H> operator * (matrix<T, H, W> const & a, array<T, W> const & b) {
    array<T, H> c = {};
    REP (y, H) REP (z, W) c[y] += a[y][z] * b[z];
    return c;
}
template <typename T, size_t N>
matrix<T, N, N> matrix_unit() {
    matrix<T, N, N> a = {};
    REP (i, N) a[i][i] = 1;
    return a;
}

constexpr int MOD[4] = { (int)1e9 + 7, (int)1e9 + 9, (int)1e9 + 21, (int)1e9 + 33 };
constexpr int BASE[4] = { 10007, 10009, 10037, 10039 };
template <int k> using mmat = matrix<mint<MOD[k]>, 2, 2>;

template <int k>
vector<mmat<k> > get_cumulative_sum(int n, string const & s) {
    const mmat<k> INCR = {{ {{ 1, +1 }}, {{ 0, 1 }} }};
    const mmat<k> DECR = {{ {{ 1, -1 }}, {{ 0, 1 }} }};
    const mmat<k> NEXT = {{ {{ 1,  0 }}, {{ 0, BASE[k] }} }};
    const mmat<k> PREV = {{ {{ 1,  0 }}, {{ 0, mint<MOD[k]>(BASE[k]).inv() }} }};

    vector<mmat<k> > f(n + 1);
    f[0] = matrix_unit<mint<MOD[k]>, 2>();
    REP (i, n) {
        auto const & g =
            s[i] == '+' ? INCR :
            s[i] == '-' ? DECR :
            s[i] == '<' ? NEXT :
            s[i] == '>' ? PREV :
            *(mmat<k> *)nullptr;
        f[i + 1] = g * f[i];
    }
    return f;
}

array<int, 4> apply_matrices(mmat<0> const & f0, mmat<1> const & f1, mmat<2> const & f2, mmat<3> const & f3) {
    const array<mint<MOD[0]>, 2> v0 = {{ 0, 1 }};
    const array<mint<MOD[1]>, 2> v1 = {{ 0, 1 }};
    const array<mint<MOD[2]>, 2> v2 = {{ 0, 1 }};
    const array<mint<MOD[3]>, 2> v3 = {{ 0, 1 }};
    int a0 = (f0 * v0)[0].data;
    int a1 = (f1 * v1)[0].data;
    int a2 = (f2 * v2)[0].data;
    int a3 = (f3 * v3)[0].data;
    array<int, 4> a = {{ a0, a1, a2, a3 }};
    return a;
}

ll solve(int n, string const & s) {
    auto f0 = get_cumulative_sum<0>(n, s);
    auto f1 = get_cumulative_sum<1>(n, s);
    auto f2 = get_cumulative_sum<2>(n, s);
    auto f3 = get_cumulative_sum<3>(n, s);

    map<array<int, 4>, int> cnt_a;
    REP (l, n + 1) {
        auto a = apply_matrices(f0[l], f1[l], f2[l], f3[l]);
        cnt_a[a] += 1;
    }

    ll cnt = 0;
    REP (l, n + 1) {
        auto a = apply_matrices(f0[l], f1[l], f2[l], f3[l]);
        cnt_a[a] -= 1;

        auto b = apply_matrices(f0[n] * f0[l], f1[n] * f1[l], f2[n] * f2[l], f3[n] * f3[l]);
        cnt += cnt_a[b];
    }
    return cnt;
}

int main() {
    int n; string s; cin >> n >> s;
    cout << solve(n, s) << endl;
    return 0;
}
```

<!-- {% endraw %} -->

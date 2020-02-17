---
layout: post
date: 2019-08-13T23:59:59+09:00
tags: ["competitive", "writeup"]
---

# Member SRM 489 Div 1: Hard. AppleTrees

## 問題

りんごの木の苗が $N$ 個あります。
これらすべてを数直線上の点 $0, 1, 2, \dots, D - 1$ のいずれかに植えます。
$i$ 番目の苗は他のすべての苗と最低でも $r_i$ 以上離して植えないとだめです。
可能な植え方はいくつありますか。

## 解法

動的計画法。$O(n^3 (\max r_i)^2)$。

植えられたふたつ苗の領域に (strict に) 重なりがある (つまり $|y - x| \lt r_i + r_j$) とき、それらは同じ連結成分に属すると呼ぶことにする。
この連結成分の集合を管理する。
特に、覚えておくのはその領域の大きさの総和と個数だけでよい。
さらに $0, D - 1$ 付近の処理するのために、 $r \gg \max r_i$ の苗をふたつ追加で用意して位置 $- r$ と位置 $D - 1 + r$ に固定で植えるものと考える。
このようにして、苗を $r_i$ の大きい順に $i$ 番目まで使って両端の壁に繋る連結成分を含めて連結集合を $2 + x$ 個作りその長さの総和が $y$ であるような方法の数を $\mathrm{dp}(i, x, y)$ とする。
この関数は動的計画法で計算できる。

## 考察

-   半分全列挙したくなるが無理そう
-   愚直 DP は $\mathrm{dp} : \mathcal{P}(N) \times D \times N \to \mathbb{N}$ とかなので無理そう
-   $2^{40} \approx 10^{12}$ なので厳しい
-   でも $N \le 50$ でなくて $N \le 40$ なのでそういうことでは？ (メタ読み)
-   離して置く場合は独立性が高いので後で好きに順番入れ換えたりすればよい。半径 $r_i$ の円が重なってる苗同士に辺を張ってできる連結成分ごとに考える感じでは
-   $r_i \le 40$ とやたら小さいことを使いたい
-   苗の集合 $X \subseteq N$ と大きさ $d \le \sum r_i$ をとって、$X$ の苗をちょうど使ってできる大きさ $d$ の連結成分の作り方の数 $f(X, r)$ を求める感じにしたい
-   $D$ の大きさは無視できるかもだが、それでも $2^N$ が大きすぎる
-   苗を $r_i$ の大きい方から使っていくことにする。このとき、植えると単に区間が分割される感じになる
-   長すぎる区間はあまり区別しなくてよい。長すぎる区間の個数とそれらの長さの総和だけ持ってたら十分だったりしそう
-   大きい順に $i$ 番目まで使って小さい区間の長さの重複集合が $X$ かつ大きい区間の長さの総和が $D - y$ かつ大きい区間の個数が $z$ 個であるような方法の数を $\mathrm{dp}(i, X, y, z)$ とする？ まだきびしい
-   大きい順に $i$ 番目まで使って連結集合を $x$ 個作りその長さの総和が $y$ であるような方法の数を $\mathrm{dp}(i, x, y)$ とする。いけそう

(ここまでだらだらやって 100 分)

-   $O(N^3 (\max r_i)^3)$ になっちゃったけど $O(N^3 (\max r_i)^2)$ にならできて間に合いそう
-   最後に連結成分を配置するとき、それぞれの連結成分の大きさだけでなく含まれる苗の位置も分かってないと、区間 $[0, D)$ の端に置くときに困る。だめ
-   それぞれの連結成分の中で最左と最右の苗の位置を覚えておくのはさすがにだめ
-   追加で $O(N^2)$ 支払って、全体の中で最左と最右の苗の種類を固定しておくのがよさそう？
-   $O(N^5 (\max r_i)^2)$ は間に合わなさそう
-   $r \gg \max r_i$ の苗をふたつ用意して位置 $- r$ と位置 $D - 1 + r$ に置いておくのはどうか。いけそう
-   すこし修正し、大きい順に $i$ 番目まで使って、両端の壁に繋る連結成分を含めて連結集合を $2 + x$ 個作りその長さの総和が $y$ であるような方法の数を $\mathrm{dp}(i, x, y)$ とする

(AC できた。255 分)

## メモ

-   「大きすぎるので (繋がってないけど) 繋がっているということにしてよい」という不思議な感じのやつ、なんとなく厳格有限主義とか $\mathrm{PA}$ の超準モデルとかが思い出される
-   「円と円の衝突判定のときは大きさを一方に移してよい」みたいな幾何テクとも同じ原理ぽい
-   要点:
    -   「連結成分の概念」
    -   「大きさの総和と個数のみを持てばいい、順序や中の点の位置は持たなくていい」
    -   「壁を固定された連結成分と見なす」

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;
class AppleTrees { public: int theCount(int D, vector<int> r); };

template <int32_t MOD>
struct mint {
    int32_t value;
    mint() : value() {}
    mint(int64_t value_) : value(value_ < 0 ? value_ % MOD + MOD : value_ >= MOD ? value_ % MOD : value_) {}
    inline mint<MOD> operator + (mint<MOD> other) const { int32_t c = this->value + other.value; return mint<MOD>(c >= MOD ? c - MOD : c); }
    inline mint<MOD> operator * (mint<MOD> other) const { int32_t c = (int64_t)this->value * other.value % MOD; return mint<MOD>(c < 0 ? c + MOD : c); }
    inline mint<MOD> & operator += (mint<MOD> other) { this->value += other.value; if (this->value >= MOD) this->value -= MOD; return *this; }
    inline mint<MOD> & operator *= (mint<MOD> other) { this->value = (int64_t)this->value * other.value % MOD; if (this->value < 0) this->value += MOD; return *this; }
    inline mint<MOD> operator - () const { return mint<MOD>(this->value ? MOD - this->value : 0); }
    mint<MOD> pow(uint64_t k) const {
        mint<MOD> x = *this, y = 1;
        for (; k; k >>= 1) {
            if (k & 1) y *= x;
            x *= x;
        }
        return y;
    }
    mint<MOD> inv() const {
        assert (value != 0);
        int64_t a = value, b = MOD;
        int64_t x = 0, y = 1;
        for (int64_t u = 1, v = 0; a; ) {
            int64_t q = b / a;
            x -= q * u; std::swap(x, u);
            y -= q * v; std::swap(y, v);
            b -= q * a; std::swap(b, a);
        }
        assert (value * x + MOD * y == b);
        assert (b == 1);
        return x;
    }
    inline bool operator == (mint<MOD> other) const { return value == other.value; }
    inline bool operator != (mint<MOD> other) const { return value != other.value; }
};
template <int32_t MOD> mint<MOD> operator * (int64_t value, mint<MOD> n) { return mint<MOD>(value) * n; }

template <int32_t MOD>
mint<MOD> fact(int n) {
    static std::vector<mint<MOD> > memo(1, 1);
    while (n >= memo.size()) {
        memo.push_back(memo.back() * mint<MOD>(memo.size()));
    }
    return memo[n];
}
template <int32_t PRIME>
mint<PRIME> inv_fact(int n) {
    static std::vector<mint<PRIME> > memo;
    if (memo.size() <= n) {
        int l = memo.size();
        int r = n * 1.3 + 100;
        memo.resize(r);
        memo[r - 1] = fact<PRIME>(r - 1).inv();
        for (int i = r - 2; i >= l; -- i) {
            memo[i] = memo[i + 1] * (i + 1);
        }
    }
    return memo[n];
}

template <int32_t MOD>
mint<MOD> choose(int n, int r) {
    assert (0 <= r and r <= n);
    return fact<MOD>(n) * inv_fact<MOD>(n - r) * inv_fact<MOD>(r);
}

constexpr int MOD = 1e9 + 7;
int AppleTrees::theCount(int d, vector<int> r) {
    int n = r.size();
    int sum_r = accumulate(ALL(r), 0);
    int e = min(d, 2 * sum_r + 1);
    sort(r.rbegin(), r.rend());

    vector<vector<vector<mint<MOD> > > > dp(n + 1, vector<vector<mint<MOD> > >(n + 3, vector<mint<MOD> >(e)));
    dp[0][2][0] = 1;
    REP (i, n) {
        REP3 (k, 2, n + 3) REP (l, e) if (dp[i][k][l] != 0) {
            // make a new component
            if (k + 1 < n + 3) {
                int l0 = l + 2 * r[i];
                if (l0 < e) {
                    dp[i + 1][k + 1][l0] += dp[i][k][l];
                }
            }
            // extend an existing component
            REP3 (overwrap, 1, r[i] + 1) {
                int l1 = l + 2 * r[i] - overwrap;
                if (l1 < e) {
                    int k1 = 1 + 2 * (k - 2) + 1;
                    dp[i + 1][k][l1] += k1 * dp[i][k][l];
                }
            }
            // join two existing components
            REP3 (overwrap, 2, 2 * r[i] + 1) {
                int k3 = overwrap - 1 - max(0, 2 * (overwrap - 1 - r[i]));
                int l2 = l + 2 * r[i] - overwrap;
                if (l2 < e) {
                    int k2 = (k == 2 ? 1 : (k - 2) + (k - 2) * (k - 3) + (k - 2));
                    dp[i + 1][k - 1][l2] += k2 * k3 * dp[i][k][l];
                }
            }
        }
    }

    mint<MOD> answer = 0;
    if (d - 1 < e) {
        answer += dp[n][1][d - 1];
    }
    REP3 (k, 2, n + 3) {
        REP (l, e) {
            answer += choose<MOD>(d - 1 - l + (k - 2), k - 2) * fact<MOD>(k - 2) * dp[n][k][l];
        }
    }
    return answer.value;
}
```

## リンク

-   <https://community.topcoder.com/stat?c=problem_statement&pm=11213>

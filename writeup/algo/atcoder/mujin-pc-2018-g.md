---
redirect_from:
layout: post
date: 2018-08-18T08:06:07+09:00
tags: [ "competitive", "writeup", "atcoder", "z-module", "linear-aldgebra", "combination", "complement" ]
"target_url": [ "https://beta.atcoder.jp/contests/mujin-pc-2018/tasks/mujin_pc_2018_g" ]
---

# Mujin Programming Challenge 2018: G - 移動

## solution

代数学して整理し補集合を数える。クエリあたり$O(1)$。

問題は次のように整理できる:

>   どのふたつをとっても $\mathbb{R}^2$ のvectorsとして線形独立な $e_1, e_2, e_3 \in \mathbb{Z}^2$ と自然数 $K$ が与えられる。
その制限された整数結合で得られるvectorsの数 $$\# \left\{ t_1 e_1 + t_2 e_2 + t_3 e_3 \mid t_1, t_2, t_3 \in \mathbb{N} \land t_1 + t_2 + t_3 \le K \right\}$$ を答えよ。

$2$次元のvectorで$3$本あるのでひとつを残りふたつの線形結合で表したい。
しかし今回はそうでないので必ずしも $e_3 = a_1 e_1 + a_2 e_2$ な $a_1, a_2 \in \mathbb{Z}$ はない。
係数の構造が $\mathbb{R}$ や $\mathbb{Q}$ などの体ならvector空間になるが $\mathbb{Z}$ は環でしかないため。
それでも加群にはなっていて $a_3 e_3 = a_1 e_1 + a_2 e_2$ な $a_1, a_2, a_3 \in \mathbb{Z}$ ならある。
これは通常の線形代数をすこし修正してやれば求まる。

さらに入力の制約などから $a_1, a_2 \gt 0$ かつ $a_3 \ne 0$ であると仮定してよい。
$a_3 \lt 0$ のときは $t_1 \ge a_1 \land t_2 \ge a_2 \land t_3 \ge a_3$ なら $t_i$ それぞれから $a_i$ 引けばよいので、つまりは $$\# \left\{ (t1, t2, t3) \mid t1 + t2 + t3 \le k \land t1 \lt a1 \lor t2 \lt a2 \lor t3 \lt a3 \right\}$$ を計算すればよい。
これは補集合を数えるようにすれば求まる。
組み合わせ${} _ n C _ r$の計算が出てくるが$r = 3$のみしか関与しないため愚直に計算する。
$a_3 \gt 0$ のときはさらに $a_1 + a_2$ と $a_3$ の大小で場合分けし、それぞれ同様にする。

実質線形代数部分の途中でoverflowする可能性があるがboostで任意精度整数演算をすればよい (おそらくは非想定)。
後の議論と密結合にして$a_1, a_2, a_3$が不要そうなら計算しないなどすれば回避できるのだと思っているが未確認である。

## note

ちょうど雪江代数で$A$加群や$\mathbb{Z}$加群を言っていたところに来たので実質演習問題。

## implementation

``` c++
#include <iostream>
#include <boost/multiprecision/cpp_int.hpp>
using integer = boost::multiprecision::cpp_int;
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
    inline mint<MOD> operator /  (mint<MOD> other) const { return *this *  other.inv(); }
    inline mint<MOD> operator /= (mint<MOD> other)       { return *this *= other.inv(); }
    inline bool operator == (mint<MOD> other) const { return data == other.data; }
    inline bool operator != (mint<MOD> other) const { return data != other.data; }
};

constexpr int MOD = 998244353;

mint<MOD> binomial(integer n, int r) {
    assert (r == 3);
    if (n < r) return 0;
    mint<MOD> m = (int)(n % MOD);
    return m * (m - 1) * (m - 2) / mint<MOD>(6);
}

// count:
//     if a3 > 0
//         # { (t1, t2, t3) | t1 + t2 + t3 <= k, t1 < a1 or t2 < a2 or t3 < a3 }
//     else
//         if a1 + a2 < - a3
//             # { (t1, t2, t3) | t1 + t2 + t3 <= k, t3 < - a3 }
//         if a1 + a2 > - a3
//             # { (t1, t2, t3) | t1 + t2 + t3 <= k, t1 < a1 or t2 < a2 }
mint<MOD> solve1(integer a1, integer a2, integer a3, int k) {
    assert (a1 > 0 and a2 > 0 and a3 != 0);
    if (a3 > 0) {
        return binomial(k + 3, 3) - binomial(k - a1 - a2 - a3 + 3, 3);
    } else {
        if (a1 + a2 < - a3) {
            return binomial(k + 3, 3) - binomial(k + a3 + 3, 3);
        } else {
            return binomial(k + 3, 3) - binomial(k - a1 - a2 + 3, 3);
        }
    }
}

// solve:
//     a3 x3 = a1 x1 + a2 x2
//     a3 y3 = a1 y1 + a2 y2
tuple<integer, integer, integer> z_module_solze(integer x1, integer y1, integer x2, integer y2, integer x3, integer y3) {
    auto mul = [&](integer kx, integer ky) {
        x1 *= kx; x2 *= kx; x3 *= kx;
        y1 *= ky; y2 *= ky; y3 *= ky;
    };
    if (y1 != 0) {
        if (x1 == 0) {
            swap(x1, y1);
            swap(x2, y2);
            swap(x3, y3);
        } else {
            integer d1 = boost::multiprecision::gcd(x1, y1);
            mul(y1 / d1, x1 / d1);
            y1 -= x1;
            y2 -= x2;
            y3 -= x3;
        }
    }
    assert (y1 == 0);
    if (x2 != 0) {
        assert (y2 != 0);  // by constraints of the problem
        integer d2 = boost::multiprecision::gcd(x2, y2);
        mul(y2 / d2, x2 / d2);
        x1 -= y1;
        x2 -= y2;
        x3 -= y3;
    }
    assert (y1 == 0 and x2 == 0);
    integer a3 = x1 * y2;
    integer a1 = x3 * y2;
    integer a2 = y3 * x1;
    integer d = boost::multiprecision::gcd(a3, boost::multiprecision::gcd(a1, a2));
    a1 /= d;
    a2 /= d;
    a3 /= d;
    return make_tuple(a1, a2, a3);
}

// let:
//     e1 = (x1, y1)
//     e2 = (x2, y2)
//     e3 = (x3, y3)
// count:
//     # { t1 e1 + t2 e2 + t3 e3 | t1 + t2 + t3 <= k }
mint<MOD> solve(int x1, int y1, int x2, int y2, int x3, int y3, int k) {
    integer a1, a2, a3; tie(a1, a2, a3) = z_module_solze(x1, y1, x2, y2, x3, y3);
    a3 *= -1;
    assert (a1 * x1 + a2 * x2 + a3 * x3 == 0);
    assert (a1 * y1 + a2 * y2 + a3 * y3 == 0);
    assert (a1 != 0 and a2 != 0 and a3 != 0);  // by constraints of the problem
    if ((a1 < 0) + (a2 < 0) + (a3 < 0) >= 2) {
        a1 *= -1;
        a2 *= -1;
        a3 *= -1;
    }
    if (a1 > 0 and a2 > 0 and a3 > 0) {
        // nop
    } else {
        if (a1 < 0) {
            swap(a1, a3);
            swap(x1, x3);
            swap(y1, y3);
        }
        if (a2 < 0) {
            swap(a2, a3);
            swap(x2, x3);
            swap(y2, y3);
        }
        assert (a1 > 0 and a2 > 0 and a3 < 0);
    }
    return solve1(a1, a2, a3, k);
}

int main() {
    int q; cin >> q;
    while (q --) {
        int a, b, c, d, e, f, k;
        cin >> a >> b >> c >> d >> e >> f >> k;
        auto ans = solve(a, b, c, d, e, f, k);
        cout << ans.data << endl;
    }
    return 0;
}
```

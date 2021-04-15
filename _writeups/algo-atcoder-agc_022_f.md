---
layout: post
date: 2018-09-15T04:03:49+09:00
tags: [ "competitive", "writeup", "atcoder", "agc", "polynomial", "dp", "tree", "ast" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc022/tasks/agc022_f" ]
redirect_from:
  - /writeup/algo/atcoder/agc_022_f/
  - /writeup/algo/atcoder/agc-022-f/
---

# AtCoder Grand Contest 022: F - Checkers

## 解法

### 概要

多項式として整理し構文木を見る。
正規な対象のみを数えたい(典型)ので木を折り畳んで潰す。
$$O(N^6)$$ あるいは埋め込みで $$O(1)$$。

### 詳細

まず問題を整理しよう。
初等的な言葉だけで言い換えてあるが、分かりやすくすると次のようになる。

>   $$N$$変数多項式環$$\mathbb{Z}[x_1, \dots, x_N]$$とこの上の$$2$$項演算$$f \star g = 2f - g$$を考える。
    元$$x_1, \dots, x_N \in \mathbb{Z}[x_1, \dots, x_N]$$を任意に並べ替えて任意に括弧を入れて式(を表現する記号列)を作ったとき (例えば $$N = 5$$ の設定で $$((x_2 \star x_4) \star x_3) \star (x_5 \star x_1)$$ などのような式が作れる) その式の値として有り得る多項式の数はいくつか。
    $$10^9 + 7$$で割ったあまりを求めよ。

組み換えて得られた斉次多項式の比較は係数だけ考えればよいことも明らか。
このようなときは主に以下のふたつの選択肢がある。
今回(1.)は難しいので(2.)をすることになる。

1.  結果(係数の列)で有り得るものを直接数える
2.  操作(構文木)で有り得るものを重複を排除しながら数える
3.  (これらの補集合を数える)

構文木を考え葉に最終的に付く係数を書くと、例えば($$45^\circ$$回転させ)次のようになる。

```
    *---------*-----*-----(-1)
    |         |     |
    |       (-2)    *-----(-2)
    *--(-2)         |
    |               |
    *--(-4)        (4)
    |
   (8)
```

なんとなく格子のような構造が見える。
これを数えていきたい。
各節点で左右の葉の数を総当たりするなどではだめで、上手く重複を排除したい。
検討するのは例えば、適当に木を回転させて格子で見たときちょうど三角形になるようにすればどうか、など。
しかしここで正解は木を使わないことで、横幅を$$2$$にして以下のような梯子状の構造を考えるとよい。

```
     ,------------->
    *<--------------(-1)
   || `------------>  |
   ||                 |
   ||                 |
    *----------->(-2,-2,-2)
   ||
   ||
   ||
   (4)------------->(-4)
    |
    |
    |
   (8)
```

このようにすれば重複が綺麗に消える。
現在の段数、左側の縦の辺の数、右側の縦の辺の数、今までに作った葉の数、を持てばよいため$$\mathrm{dp} : (N + 1)^4 \to \mathbb{F} _ {10^9 + 7}$$のDPで計算できる。

## メモ

-   自力で解けたのでうれしい
-   editorialでは謎必要条件を空中から取り出しててこわい

## 実装

``` c++
#include <cassert>
#include <functional>
#include <iostream>
#include <vector>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

template <int32_t MOD>
struct mint {
    int64_t value;  // faster than int32_t a little
    mint() = default;  // value is not initialized
    mint(int64_t value_) : value(value_) {}  // assume value is in proper range
    inline mint<MOD> operator + (mint<MOD> other) const { int64_t c = this->value + other.value; return mint<MOD>(c >= MOD ? c - MOD : c); }
    inline mint<MOD> operator - (mint<MOD> other) const { int64_t c = this->value - other.value; return mint<MOD>(c <    0 ? c + MOD : c); }
    inline mint<MOD> operator * (mint<MOD> other) const { int64_t c = this->value * int64_t(other.value) % MOD; return mint<MOD>(c < 0 ? c + MOD : c); }
    inline mint<MOD> & operator += (mint<MOD> other) { this->value += other.value; if (this->value >= MOD) this->value -= MOD; return *this; }
    inline mint<MOD> & operator -= (mint<MOD> other) { this->value -= other.value; if (this->value <    0) this->value += MOD; return *this; }
    inline mint<MOD> & operator *= (mint<MOD> other) { this->value = this->value * int64_t(other.value) % MOD; if (this->value < 0) this->value += MOD; return *this; }
    mint<MOD> pow(uint64_t k) const {
        mint<MOD> x = *this;
        mint<MOD> y = 1;
        for (uint64_t i = 1; i and (i <= k); i <<= 1) {
            if (k & i) y *= x;
            x *= x;
        }
        return y;
    }
    mint<MOD> inv() const { return pow(MOD - 2); }  // MOD must be a prime
};

template <int32_t MOD>
mint<MOD> fact(int n) {
    static vector<mint<MOD> > memo(1, 1);
    while (n >= memo.size()) {
        memo.push_back(memo.back() * mint<MOD>(memo.size()));
    }
    return memo[n];
}
template <int32_t PRIME>
mint<PRIME> inv_fact(int n) {
    static vector<mint<PRIME> > memo;
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

mint<MOD> solve(int n) {
    auto used = vectors(n + 1, max(2, n), n, n + 1, (char)false);
    auto memo = vectors(n + 1, max(2, n), n, n + 1, mint<MOD>());
    function<mint<MOD> (int, int, int, int)> dp = [&](int k, int pos, int neg, int cnt) -> mint<MOD> {
        if (pos + neg == 0) return (cnt == 0);
        if (pos + neg > cnt) return 0;
        assert (k <= n);
        char & used1 = used[k][pos][neg][cnt];
        auto & memo1 = memo[k][pos][neg][cnt];
        if (used1) return memo1;
        used1 = true;
        REP (pos1, cnt + 1) {
            REP (neg1, cnt + 1) {
                int pos2 = pos + neg1 - pos1;
                int neg2 = neg + pos1 - neg1;
                if (0 <= pos2 and 0 <= neg2 and pos2 + neg2 <= cnt) {
                    memo1 += dp(k + 1, pos1, neg1, cnt - pos2 - neg2) * choose<MOD>(cnt, pos2) * choose<MOD>(cnt - pos2, neg2);
                }
            }
        }
        return memo1;
    };
    return dp(0, 1, 0, n);
}

int main() {
    int n; cin >> n;
    cout << solve(n).value << endl;
    return 0;
}
```

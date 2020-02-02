---
layout: post
title: "AtCoder Regular Contest 089: F - ColoringBalls"
date: 2018-09-28T05:29:48+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "counting", "dp", "longest-common-prefix", "experiment" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc089/tasks/arc089_d" ]
---

## 解法

### 概要

うまく同値関係で割るやつ。
難しい。
計算量不明。

### 詳細

結果の色の列を同値関係で割って、代表元だけを数えよう。

同じ色が続く部分はまとめてしまい、白色の位置で分割し、さらに分割されたそれぞれの部分の順番を並び換え整列する。
これは典型。
つまり `rrwrbrrbbwwrwrb` という文字列は ( `r`, `r`, `rb`, `brb` ) という単語列として整理される。

上の整理により `r` と `b` が交互に現れる単語のみ考えてよい。
次のような形の$4$種の単語はどれも作成に必要な入力の形が同じであることが(おそらくは注意深い観察により)分かる(はず)。

-   `_brbr...rb_`
-   `_brbr...rbr`
-   `rbrbr...rb_`
-   `rbrbr...rbr`

具体的には `rb???...?` という形で消費する。
`r` 単体を例外としてすべてこの `?` の数の違いだけなので、すべての単語は構成に必要な入力の長さで分類できる。
単語列 ( `r`, `r`, `rb`, `brb` ) はさらに ( 1, 1, 2, 3 ) という単調な数列(あるいは多重集合)としてまとめることができる。

このような数列で見るべきもの数は$N \le 70$であることからそう多くはないことが(これはたぶん直感と実験により)分かる(はず)。

数列が与えられたときにそのような塗り方が入力から可能かどうかは$O(K)$の貪欲で求まる。
ここまでの議論を元にすれば、この貪欲はそう難しくない。
ここでは$N$の値はまったく使わなくてよいことに注意する。

数列$f$をひとつ固定したとき、これから生成される本来のボールの色の列の数は $O(N^2|f|)$ のDPで求まる。
さらにこのDPの形をよく見れば、ふたつの数列$f, f'$のDPに対し数列の共通接頭辞の部分についてはDPの表を共有できることが分かる。
数列を適当な順番で整列して最長共通接頭辞が長くなるようにしておけばその分だけ速くなってなんとか間に合うようになる。

## メモ

解説見て6時間。きびしい。でもおもしろい

## 実装

``` c++
#include <algorithm>
#include <cassert>
#include <functional>
#include <iostream>
#include <string>
#include <vector>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

template <int32_t MOD>
struct mint {
    int64_t value;  // faster than int32_t a little
    mint() = default;  // value is not initialized
    mint(int64_t value_) : value(value_) {}  // assume value is in proper range
    inline mint<MOD> operator + (mint<MOD> other) const { int64_t c = this->value + other.value; return mint<MOD>(c >= MOD ? c - MOD : c); }
    inline mint<MOD> operator * (mint<MOD> other) const { int64_t c = this->value * int64_t(other.value) % MOD; return mint<MOD>(c < 0 ? c + MOD : c); }
    inline mint<MOD> & operator += (mint<MOD> other) { this->value += other.value; if (this->value >= MOD) this->value -= MOD; return *this; }
    inline mint<MOD> & operator *= (mint<MOD> other) { this->value = this->value * int64_t(other.value) % MOD; if (this->value < 0) this->value += MOD; return *this; }
    mint<MOD> pow(uint64_t k) const {
        mint<MOD> x = *this, y = 1;
        for (; k; k >>= 1) {
            if (k & 1) y *= x;
            x *= x;
        }
        return y;
    }
    mint<MOD> inv() const { return pow(MOD - 2); }  // MOD must be a prime
};
template <int32_t MOD> ostream & operator << (ostream & out, mint<MOD> n) { return out << n.value; }

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


/**
 * group = 1:
 *    R
 *
 * group = 2:
 *    _B_
 *    _BR
 *    RB_
 *    RBR
 *
 * group = 4:
 *    _BRBRB_
 *    _BRBRBR
 *    RBRBRB_
 *    RBRBRBR
 */

constexpr int MOD = 1e9 + 7;

bool is_constructible_sequence(int k, string const & s, vector<int> const & f) {
    int r = 0, b = 0;  // indices, 0 <= b <= r <= f.size()
    int q = 0;
    for (char c : s) {
        if (c == 'r' and r < f.size()) {
            ++ r;
        } else if (c == 'b' and b < r) {
            assert (f[b] >= 2);
            q += f[b] - 2;
            ++ b;
        } else if (q) {
            -- q;
        }
        while (b < r and f[b] == 1) {
            ++ b;
        }
    }
    return r == f.size() and b == f.size() and not q;
}

vector<vector<int> > list_constructible_sequences(int n, int k, string const & s) {
    vector<vector<int> > fs;
    vector<int> f;
    function<void (int, int)> go = [&](int used, int group) {
        if (group == 0) {
            if (is_constructible_sequence(k, s, f)) {
                fs.push_back(f);
            }
        } else {
            go(used, group - 1);
            int next_used = used + (not not used) + max(1, 2 * group - 3);
            if (next_used <= n) {
                f.push_back(group);
                go(next_used, group);
                f.pop_back();
            }
        }
    };
    go(0, max(2, n));
    return fs;
}

void initialize_dp(int n, vector<mint<MOD> > & cur) {
    cur.assign(n + 1, 1);
}
void step_dp(int n, int i, int f_i, vector<mint<MOD> > const & prv, vector<mint<MOD> > & cur) {
    cur.assign(n + 1, 0);
    if (f_i == 1) {
        mint<MOD> acc = 0;
        REP (j, n) {
            cur[j + 1] += cur[j];  // use a white ball
            int j1 = j - (i != 0);
            if (j1 >= 0) acc += prv[j1];
            cur[j + 1] += acc;  // use red balls
        }
    } else {
        int core = max(1, f_i * 2 - 3);
        vector<mint<MOD> > cnt(n + 1);
        REP3 (dj, core, n + 1) {
            for (int size : { core, core + 1, core + 1, core + 2 }) {
                if (dj >= size) {
                    cnt[dj] += choose<MOD>(dj - 1, size - 1);
                }
            }
        }
        REP (j, n) {
            cur[j + 1] += cur[j];  // use a white ball
            REP3 (dj, core, n - j + (i == 0)) {
                cur[j + (i != 0) + dj] += cnt[dj] * prv[j];  // use red and blue balls (after a white ball)
            }
        }
    }
}
mint<MOD> get_dp_result(int n, vector<mint<MOD> > const & cur) {
    return cur[n];
}

mint<MOD> count_shuffled_sequence(vector<int> const & f) {
    mint<MOD> acc = 1;
    for (int l = 0; l < f.size(); ) {
        int r = l;
        while (r < f.size() and f[l] == f[r]) ++ r;
        acc *= choose<MOD>(r, r - l);
        l = r;
    }
    return acc;
}

mint<MOD> solve(int n, int k, string const & s) {
    mint<MOD> acc = 0;
    auto fs = list_constructible_sequences(n, k, s);
    assert (is_sorted(ALL(fs)));
    auto dp = vectors(n + 1, n + 1, mint<MOD>());
    initialize_dp(n, dp[0]);
    vector<int> prv_f;
    for (auto const & cur_f : fs) {
        int i = 0;
        while (i < prv_f.size() and i < cur_f.size() and prv_f[i] == cur_f[i]) {
            ++ i;
        }
        while (i < cur_f.size()) {
            step_dp(n, i, cur_f[i], dp[i], dp[i + 1]);
            ++ i;
        }
        acc += get_dp_result(n, dp[cur_f.size()]) * count_shuffled_sequence(cur_f);
        prv_f = cur_f;
    }
    return acc;
}

int main() {
    int n, k; cin >> n >> k;
    string s; cin >> s;
    cout << solve(n, k, s).value << endl;
    return 0;
}
```

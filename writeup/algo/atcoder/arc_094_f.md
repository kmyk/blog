---
layout: post
date: 2018-09-29T02:49:01+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "dp", "invariant" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc094/tasks/arc094_d" ]
redirect_from:
  - /writeup/algo/atcoder/arc_094_f/
  - /writeup/algo/atcoder/arc-094-f/
---

# AtCoder Regular Contest 094: F - Normalization

## 解法

### 概要

上手な不変条件を見付けるとそれが必要十分になってるやつ。
$O(|S|)$。

### 詳細

次を確認する:

-   操作後の文字列には常に同じ文字が連続する部分がある
-   $\phi(a) = 0, \phi(b) = 1, \phi(c) = 2$ とおいて $\sum \phi(S_i) \equiv m \pmod{3}$ を考えたときこの値 $m \equiv \phi(S)$ は操作によって不変

これは構築できる文字列の必要条件になっている。

いくつか例外を除いて、これは十分条件にもなっている。
つまり、次の条件を満たす文字列 $T$ の個数を数えればよい。
これは $|S|, m$ だけに依存する単純なDP。

-   同じ文字が連続する部分がある
-   入力 $S$ と同じ $m$ の値を持つ

加えて $S$ に同じ文字が連続する部分がない場合は $T = S$ の分の $1$ を足す。

ただし次は例外なので別に処理する。

-   $S$ がすべて同じ文字から成る場合
-   $\|S\| = 2, 3$ の場合

## メモ

-   mod 3は天才感ある
    -   $a, b, c$ それぞれの個数の差の変化を観察すると出るらしい: [ARC094 F Normalization - てんぷらのぷらはC++のぷら](https://tempura0224.hatenablog.com/entry/2018/04/18/151712)
    -   典型として覚えた方が早そう
-   ところでこの十分性なんで成り立つの

## 実装

``` c++
#include <algorithm>
#include <array>
#include <functional>
#include <iostream>
#include <numeric>
#include <string>
#include <unordered_set>
#include <vector>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

template <int32_t MOD>
struct mint {
    int64_t value;
    mint() = default;
    mint(int64_t value_) : value(value_) {}
    inline mint<MOD> operator + (mint<MOD> other) const { int64_t c = this->value + other.value; return mint<MOD>(c >= MOD ? c - MOD : c); }
    inline mint<MOD> & operator += (mint<MOD> other) { this->value += other.value; if (this->value >= MOD) this->value -= MOD; return *this; }
};


constexpr int MOD = 998244353;

mint<MOD> solve1(string s) {
    unordered_set<string> used;
    function<void (void)> go = [&]() {
        if (used.count(s)) return;
        used.insert(s);
        REP (i, s.length() - 1) {
            if (s[i] != s[i + 1]) {
                char x = s[i];
                char y = s[i + 1];
                s[i] = s[i + 1] = 'a' ^ 'b' ^ 'c' ^ x ^ y;
                go();
                s[i] = x;
                s[i + 1] = y;
            }
        }
    };
    go();
    return used.size();
}

mint<MOD> solve2(int n, int m, bool is_all_different) {
    auto dp = vectors(n, array<array<mint<MOD>, 4>, 3>());
    dp[0][0][0] = 1;  // "a"
    dp[0][1][1] = 1;  // "b"
    dp[0][2][2] = 1;  // "c"
    REP (i, n - 1) {
        REP (j, 3) {
            REP (last_c, 4) {
                REP (c, 3) {
                    int next_c = (last_c == 3 or (last_c == c) ? 3 : c);
                    dp[i + 1][(j + c) % 3][next_c] += dp[i][j][last_c];  // add c
                }
            }
        }
    }
    return dp[n - 1][m][3] + is_all_different;
}

mint<MOD> solve(string const & s) {
    int n = s.length();
    if (n < 4) return solve1(s);

    bool is_all_same = (count(ALL(s), s.front()) == n);
    if (is_all_same) return 1;

    bool is_all_different = true;
    REP (i, n - 1) {
        if (s[i] == s[i + 1]) {
            is_all_different = false;
        }
    }

    int m = (accumulate(ALL(s), 0) - n * 'a') % 3;
    return solve2(n, m, is_all_different);
}

int main() {
    string s; cin >> s;
    cout << solve(s).value << endl;
    return 0;
}
```

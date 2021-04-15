---
redirect_from:
  - /writeup/algo/atcoder/kupc2018-g/
layout: post
date: 2018-10-05T04:55:44+09:00
tags: [ "competitive", "writeup", "atcoder", "kupc" ]
"target_url": [ "https://beta.atcoder.jp/contests/kupc2018/tasks/kupc2018_g" ]
---

# Kyoto University Programming Contest 2018: G - 数列を構成する問題

## 解法

### 概要

上手く$$\log p$$を使う。
$$O(N \log N)$$。

### 詳細

$$b_i$$ を展開すると次のようになる:

-   $$b_1 = a_1$$
-   $$b_2 = a_1 + a_2$$
-   $$b_3 = a_1 + a_3$$
-   $$b_4 = a_1 + a_2 + a_4$$
-   $$b_5 = a_1 + a_5$$
-   $$b_6 = a_1 + a_2 + a_3 + a_6$$
-   $$b_7 = a_1 + a_7$$
-   $$b_8 = a_1 + a_2 + a_4 + a_8$$
-   $$b_9 = a_1 + a_3 + a_9$$
-   $$b _ {10} = a_1 + a_2 + a_5 + a _ {10}$$
-   $$b _ {11} = a_1 + a _ {11}$$
-   $$b _ {12} = a_1 + a_2 + a_3 + a_4 + a_6 + a _ {12}$$
-   $$\vdots$$

明らかに分かる必要条件はふたつ:

-   素数について $$a_2 \lt a_3 \lt a_5 \lt a_7 \lt \dots$$
-   素冪について $$a_2, a_4, a_8, \dots \ge 1$$ かつ $$a_3, a_9, a _ {27} \dots \ge 1$$ かつ $$\dots$$

逆に、これら以外の数については$$a_i = 0$$とする解法がありそう。
ここまでは自然に分かる。

ここで対数を取る。
$$a _ {p^k} = \log p$$ としそれ以外は $$0$$ とすると $$\log ab = \log a + \log b$$ という準同型性からすべて上手くいく。
どうやって思い付くのかは不明。

## メモ

ここ最近で一番の天才解法

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;

vector<vector<int> > sieve_prime_factors(int n) {
    vector<vector<int> > ps(n);
    REP3 (a, 2, n) {
        if (ps[a].empty()) {
            for (int b = 2 * a; b < n; b += a) {
                for (int b1 = b; b1 % a == 0; b1 /= a) {
                    ps[b1].push_back(a);
                }
            }
        }
    }
    return ps;
}

vector<ll> solve(int n, int m, vector<int> const & c) {
    auto prime_factors = sieve_prime_factors(n + 1);
    vector<int> is_required(n + 1);
    REP (i, n + 1) {
        if (i == 0 or i == 1) continue;
        auto const & ps = prime_factors[i];
        if (ps.empty()) {
            is_required[i] = i;  // a prime
        } else if (count(ALL(ps), ps.front()) == ps.size()) {
            is_required[i] = ps.front();  // a prime-power
        }
    }
    for (int c_i : c) {
        if (is_required[c_i]) return vector<ll>();
    }

    constexpr ll MULTIPLIER = 1e9;
    vector<ll> a(n + 1);
    REP (i, n + 1) {
        if (is_required[i]) {
            a[i] = log(is_required[i]) * MULTIPLIER;
        }
    }
    return a;
}

int main() {
    int n, m; cin >> n >> m;
    vector<int> c(m);
    REP (i, m) cin >> c[i];
    auto a = solve(n, m, c);
    if (a.empty()) {
        cout << "No" << endl;
    } else {
        cout << "Yes" << endl;
        REP3 (i, 1, n + 1) cout << a[i] << ' ';
        cout << endl;
    }
    return 0;
}
```

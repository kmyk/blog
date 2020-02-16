---
layout: post
date: 2018-09-15T13:19:19+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "meet-in-the-middle", "discrete-log", "baby-step-giant-step" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc042/tasks/arc042_d" ]
redirect_from:
  - /writeup/algo/atcoder/arc-042-d/
---

# AtCoder Regular Contest 042: D - あまり

## 解法

### 概要

baby-step giant-stepやるだけ。
勝手な$$L$$に対し$$O(\min \{ L, \frac{P}{L} \sqrt{P} \})$$。

### 詳細

$$B - A$$の大きさで場合分けをする。

-   $$B - A$$ が小さい場合
    -   $$B - A + 1$$個すべて試せばよい。
-   $$B - A$$ が大きい場合
    -   勝手に$$Y = X^i$$を選んだとき高確率で$$A \le i \le B$$にできる。
        $$Y$$を$$1$$から順に試していけばすぐに引き当てられる。
        よって離散対数問題を解くだけで、これは$$P$$が十分小さいので可能。

## メモ

-   入力が乱数生成されてる保証あるけど、あまり意味がない気がする。
    やばいケースの不存在についての出題側での証明を省略するためとかだろうか。
-   埋め込みしたくなる問題形式だった

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < (int)(n); ++ (i))
#define unittest_name_helper(counter) unittest_ ## counter
#define unittest_name(counter) unittest_name_helper(counter)
#define unittest __attribute__((constructor)) void unittest_name(__COUNTER__) ()
using namespace std;
template <class T> inline void chmin(T & a, T const & b) { a = min(a, b); }

uint32_t powmod(uint32_t g, uint32_t x, uint32_t p) {
    uint32_t y = 1;
    for (; x; x >>= 1) {
        if (x & 1) y = (uint64_t)y * g % p;
        g = (uint64_t)g * g % p;
    }
    return y;
}

uint32_t modinv(uint32_t g, uint32_t p) {
    return powmod(g, p - 2, p);  // p must be a prime
}

/**
 * @description find the smallest x >= 0 s.t. g^x = y mod p
 * @note O(sqrt(p))
 * @note meet-in-the-middle; let x = a sqrt(p) + b
 */
uint32_t baby_step_giant_step(uint32_t g, uint32_t y, uint32_t p) {
    uint32_t sqrt_p = sqrt(p);

    unordered_map<uint32_t, int> baby;
    uint32_t gb = 1;
    REP (b, sqrt_p + 3) {
        baby[gb] = b;
        gb = (uint64_t)gb * g % p;
    }

    uint32_t g_sqrt_p_inv = modinv(powmod(g, sqrt_p, p), p);
    uint32_t giant = y;
    REP (a, sqrt_p + 3) {
        if (baby.count(giant)) {
            int b = baby[giant];
            uint32_t x = a * sqrt_p + b;
            return x % p;
        }
        giant = (uint64_t)giant * g_sqrt_p_inv % p;
    }
    return -1;
}

unittest {
    assert (baby_step_giant_step( 3, powmod( 3,  0,  17),  17) ==  0);
    assert (baby_step_giant_step( 3, powmod( 3, 12,  17),  17) == 12);
    assert (baby_step_giant_step(12, powmod(12, 17, 101), 101) == 17);
}


int solve(int x, int p, int a, int b) {
    assert (1 <= x and x < p);

    if (p <= a) {
        int k = a / p;
        a -= k * p;
        b -= k * p;
    }
    assert (0 <= a and a <= b and a < p);

    if (b - a + 1 <= 10000000) {
        int min_y = INT_MAX;
        int y = powmod(x, a, p);
        REP3 (i, a, b + 1) {
            chmin(min_y, y);
            y = (long long)y * x % p;
        }
        return min_y;

    } else {
        for (int y = 1; ; ++ y) {
            int i = baby_step_giant_step(x, y, p);
            if ((a <= i and i <= b) or (a <= i + p and i + p <= b)) {
                return y;
            }
        }
    }
}

int main() {
    int x, p, a, b; cin >> x >> p >> a >> b;
    cout << solve(x, p, a, b) << endl;
    return 0;
}
```

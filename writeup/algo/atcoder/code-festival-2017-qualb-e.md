---
layout: post
alias: "/blog/2017/11/10/code-festival-2017-qualb-e/"
date: "2017-11-10T23:55:48+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/code-festival-2017-qualb/tasks/code_festival_2017_qualb_e" ]
---

# CODE FESTIVAL 2017 qual B: E - Popping Balls

## 感想

-   本番解けなかったD問題より圧倒的に簡単。悲しい
-   簡単に$O(AB)$にできるが、$O(AB^2)$で間に合ってしまったのでそのまま

## solution

赤色のボールの残っている数と青色のボールの残っている数をそれぞれ$y$軸$x$軸として、$2$次元の格子上の経路数を数えるような感じのDP。適切に書けば$O(N^2)$。

$s \lt t$としてよい。
赤色のボールは(残っているなら)常に取れるので、$s, t$は青色のボールを取るためにある。
$t$は、始めて青色のボールを取り出す時に青色のボールの先頭であるような位置にするのが最良。
同様に$s$は、$t$番目の位置にボールが存在しなくなってから始めて青色のボールを取り出す時の位置とするのが最良。

そのようにしたときの経路数は表を$2$段階で埋めるようにすれば計算できる。

## implementation

``` c++
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i, m, n) for (int i = (m); (i) < int(n); ++(i))
using ll = long long;
using namespace std;

constexpr int mod = 1e9+7;
vector<vector<int> > calc_choose(int n) { // O(n^2)
    vector<vector<int> > dp(n + 1);
    dp[0].assign(1, 1);
    repeat (i, n) {
        dp[i + 1].resize(i + 2);
        repeat (j, i + 2) {
            auto & it = dp[i + 1][j];
            if (j - 1 >= 0) {
                it += dp[i][j - 1];
                if (it >= mod) it -= mod;
            }
            if (j != i + 1) {
                dp[i + 1][j] += dp[i][j];
                if (it >= mod) it -= mod;
            }
        }
    }
    return dp;
}

int main() {
    // input
    int a, b; scanf("%d%d", &a, &b);
    // solve
    auto choose = calc_choose(a + b + 3);
    ll result = 0;
    result += a + 1;
    repeat_from (x, 1, b + 1) {
        ll acc = 0;
        repeat_from (y, b - x, a + 1) {
            acc += choose[b - 1][x - 1];
            if (acc >= mod) acc -= mod;
            int nb = b - x;
            repeat (z, nb) {  // NOTE: これ消せる
                int ny = y + (nb - 1 - z);
                if (ny <= a) result += acc * choose[nb - 1][z] % mod;
            }
        }
    }
    result %= mod;
    // output
    printf("%lld\n", result);
    return 0;
}
```

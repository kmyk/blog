---
layout: post
alias: "/blog/2017/10/03/jag2017summer-day3-d/"
date: "2017-10-03T06:58:40+09:00"
tags: [ "competitive", "writeup", "atcoder", "jag-summer", "bit-dp", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/jag2017summer-day3/tasks/jag2017summer_day3_d" ]
---

# Japan Alumni Group Summer Camp 2017 Day 3: D - Janken Master

AtCoderのレートが高いとじゃんけんで有利であるのは有名事実ですが、斜め読みしてる英文中に出てくると混乱するのでやめてほしい。

## problem

$N$人でじゃんけんをする。自分以外の人はあらかじめ決められた確率に従い手を得らぶ。
引き分けならレートが最も高い人が勝ち。

## solution

bit DP。$O(N3^N)$。$t \subseteq s \subseteq n = \\{ 0, 1, \dots, n - 1 \\}$な対$(t, s)$は$3^n$個存在する。
引き分けの確率は勝ちも負けもしない確率として$1$からの引き算で求めると楽。

## implementation

``` c++
#include <array>
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i, m, n) for (int i = (m); (i) < int(n); ++(i))
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }

int main() {
    // input
    int n; scanf("%d", &n);
    int a0; scanf("%d", &a0);
    vector<int> a(n - 1);
    vector<array<double, 3> > p(n - 1);
    repeat (i, n - 1) {
        scanf("%d", &a[i]);
        repeat (hand, 3) {
            int q; scanf("%d", &q);
            p[i][hand] = q / 100.0;
        }
    }

    // solve
    vector<double> dp(1 << (n - 1));
    dp[0] = 1.0;
    repeat_from (s, 1, 1 << (n - 1)) {
        repeat (hand, 3) {
            double acc = 0;
            double q_win  = 0;
            double q_lose = 0;
            for (int t = 0; ; t = (t - s) & s) {  // t \subseteq s, t \ne s
                if (t == s) break;
                { // win
                    double q = 1.0;
                    repeat (i, n - 1) {
                        if (t & (1 << i)) {
                            q *= p[i][hand];
                        } else if (s & (1 << i)) {
                            q *= p[i][(hand + 2) % 3];
                        }
                    }
                    q_win += q;
                    acc += q * dp[t];
                }
                { // lose
                    double q = 1.0;
                    repeat (i, n - 1) {
                        if (t & (1 << i)) {
                            q *= p[i][hand];
                        } else if (s & (1 << i)) {
                            q *= p[i][(hand + 1) % 3];
                        }
                    }
                    q_lose += q;
                }
            }
            double q_draw = 1.0 - q_win - q_lose;
            int max_a = 0;
            repeat (i, n - 1) {
                if (s & (1 << i)) {
                    setmax(max_a, a[i]);
                }
            }
            if (max_a < a0) {
                acc += q_draw;
            }
            setmax(dp[s], acc);
        }
    }

    // output
    printf("%.8lf\n", dp[(1 << (n - 1)) - 1]);
    return 0;
}
```

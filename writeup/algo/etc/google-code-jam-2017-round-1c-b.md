---
layout: post
alias: "/blog/2018/04/05/google-code-jam-2017-round-1c-b/"
date: "2018-04-05T00:17:36+09:00"
tags: [ "competitive", "writeup", "gcj", "dp" ]
"target_url": [ "https://codejam.withgoogle.com/codejam/contest/dashboard?c=3274486#s=p1" ]
---

# Google Code Jam 2017 Round 1C: B. Parenting Partnering

<!-- {% raw %} -->

## solution

DP。時刻$0$で人$q \in \\{ 0, 1 \\}$が仕事をし時刻$t \le 24 \times 60$まで見て人$0$に割り当てられた時間が$t\_0 \le 12 \times 60$であり最後に人$p \in \\{ 0, 1 \\}$に割り当てられているような場合の交代回数の最小値を$\mathrm{dp}(q, t, t\_0, p) \in \mathbb{N}$とする。
時間の細かさ$T = 24 \times 60$を変数と見れば$O(T^2)$の解法。

日付けの境で交代するときも数えることに注意。
片側に寄せる貪欲でも解けるようだ。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
using namespace std;
template <class T> inline void chmin(T & a, T const & b) { a = min(a, b); }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

int solve(int n0, int n1, vector<int> const & l0, vector<int> const & r0, vector<int> const & l1, vector<int> const & r1) {
    constexpr int MINUTES = 24 * 60;
    constexpr int HALF = 12 * 60;
    vector<array<bool, 2> > reserved(MINUTES + 1, array<bool, 2>());
    REP (i, n0) {
        REP3 (t, l0[i], r0[i]) {
            reserved[t][0] = true;
        }
    }
    REP (i, n1) {
        REP3 (t, l1[i], r1[i]) {
            reserved[t][1] = true;
        }
    }
    constexpr int inf = 1e9 + 7;
    int answer = inf;
    REP (init, 2) {
        auto dp = vectors(MINUTES + 1, HALF + 1, array<int, 2>({{ inf, inf }}));
        dp[0][0][init] = 0;
        REP (t, MINUTES) {
            REP (t0, HALF + 1) {
                if (t0 - 1 >= 0 and not reserved[t][0]) {
                    chmin(dp[t + 1][t0][0], dp[t][t0 - 1][0]);
                    chmin(dp[t + 1][t0][0], dp[t][t0 - 1][1] + 1);
                }
                if (not reserved[t][1]) {
                    chmin(dp[t + 1][t0][1], dp[t][t0][0] + 1);
                    chmin(dp[t + 1][t0][1], dp[t][t0][1]);
                }
            }
        }
        chmin(answer, dp[MINUTES][HALF][init]);
        chmin(answer, dp[MINUTES][HALF][not init] + 1);
    }
    return answer;
}

int main() {
    int t; cin >> t;
    REP (i, t) {
        int ac, aj; cin >> ac >> aj;
        vector<int> c(ac), d(ac);
        REP (ic, ac) cin >> c[ic] >> d[ic];
        vector<int> j(aj), k(aj);
        REP (ij, aj) cin >> j[ij] >> k[ij];
        int answer = solve(ac, aj, c, d, j, k);
        cout << "Case #" << i + 1 << ": " << answer << endl;
    }
    return 0;
}
```

<!-- {% endraw %} -->

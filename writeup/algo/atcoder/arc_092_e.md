---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_092_e/
  - /writeup/algo/atcoder/arc-092-e/
  - /blog/2018/04/05/arc-092-e/
date: "2018-04-05T04:30:12+09:00"
tags: [ "competitive", "writeup", "arc", "dp", "greedy", "parity" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc092/tasks/arc092_c" ]
---

# AtCoder Regular Contest 092: E - Both Sides Merger

## solution

偶奇それぞれで非負のものの総和。あるいはDPして経路復元。$O(N)$あるいは$O(N^2)$。

与えられた操作を繰り返せば、例えば $(\dots, a, b, c, d, e, f, g, \dots) \to (\dots, a, b, c + e, f, g, \dots) \to (\dots, a, b + f, g, \dots) \to (\dots, a + g, \dots)$ のように、奇数個の要素を落としてその左右の和で置き換える操作となる。
元の操作は残る要素 (上の例の最後の操作では $a, g, a + g$) の偶奇を変えず、連続して行ってもそうである。
これを(いくらか削除した後の)端から行なっていくとしてよく、DPを書けば終了。
さらに観察すれば、偶数位置の項で非負のものの総和と、奇数位置の項で非負のものの総和をそれぞれ求め、その最大値が答えであることが分かる。

## note

-   偶奇で分けて貪欲でよいことに気付かずDPをした
    -   ひとつ以上選ばなければいけないことによるコーナーケースが消えるのでそう悪くもない

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
#define REP3R(i, m, n) for (int i = int(n) - 1; (i) >= int(m); -- (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;

int main() {
    // input
    int n; scanf("%d", &n);
    vector<ll> a(n); REP (i, n) scanf("%lld", &a[i]);

    // solve
    vector<ll> dp(n);
    vector<int> parent(n, -1);
    dp[0] = a[0];
    REP3 (i, 1, n) {
        dp[i] = a[i];
        for (int j = i - 2; j >= 0; j -= 2) {
            if (dp[i] < dp[j] + a[i]) {
                dp[i] = dp[j] + a[i];
                parent[i] = j;
            }
        }
    }
    int r = max_element(ALL(dp)) - dp.begin();
    ll result = dp[r];
    vector<int> path;
    REP3R (i, r + 1, n) {
        path.push_back(i);
    }
    while (true) {
        int l = parent[r];
        if (l == -1) break;
        while (l != r) {
            path.push_back((r + l) / 2);
            r -= 2;
        }
    }
    while (r != 0) {
        path.push_back(0);
        r -= 1;
    }

    // output
    printf("%lld\n", result);
    printf("%d\n", int(path.size()));
    for (int i : path) {
        printf("%d\n", i + 1);
    }
    return 0;
}
```

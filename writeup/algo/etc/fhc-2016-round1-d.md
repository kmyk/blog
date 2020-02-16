---
layout: post
redirect_from:
  - /blog/2016/01/18/fhc-2016-round1-d/
date: 2016-01-18T01:17:51+09:00
tags: [ "competitive", "writeup", "facebook-hacker-cup", "dp", "bit-dp" ]
---

# Facebook Hacker Cup 2016 Round 1 Boomerang Tournament

set dpを思い付くまでかなり時間がかかってしまった。

## [Boomerang Tournament](https://www.facebook.com/hackercup/problem/1424196571244550/)

### 解法

bit DP。
$S$に含まれる参加者でトーナメントをしたときに優勝できる参加者の集合を$T$として、${\rm dp}\_S = T$。

最低順位に関しては、対戦して負ける相手がいるかいないかのみ見ればよい。

### 実装

サイズ$k$の部分集合を列挙するテク(蟻本p143)があるようなので、それを使うべき。

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
void solve() {
    int n; cin >> n;
    vector<uint16_t> w(n);
    repeat (y,n) repeat (x,n) { int z; cin >> z; if (z) w[y] |= 1<<x; }
    vector<uint16_t> dp(1<<n); // dp[s]&(1<<y) means that y can win log|s| times when s are used
    repeat (s, 1<<n) {
        int popcnt = __builtin_popcount(s);
        if (__builtin_popcount(popcnt) != 1) continue;
        if (popcnt == 1) {
            dp[s] = s;
        } else {
            repeat (t,1<<n) if ((t & s) == t and __builtin_popcount(t) == (popcnt >> 1)) {
                int u = s & ~t;
                repeat (y,n) if (dp[t] & (1<<y) and dp[u] & w[y]) {
                    dp[s] |= 1<<y;
                }
            }
        }
    }
    repeat (y,n) {
        int popcnt = 0;
        repeat (s, 1<<n) if (dp[s] & (1<<y)) popcnt = max(popcnt, __builtin_popcount(s));
        int best = (n/popcnt)/2+1;
        int worst = __builtin_popcount(w[y]) == n-1 ? 1 : n/2+1;
        cout << best << ' ' << worst << endl;
    }
}
int main() {
    int testcases; cin >> testcases;
    repeat (testcase, testcases) {
        cout << "Case #" << testcase+1 << ": " << endl;
        solve();
    }
    return 0;
}
```

---
layout: post
redirect_from:
  - /writeup/algo/atcoder/s8pc-2-c/
  - /blog/2016/04/23/s8pc-2-c/
date: 2016-04-23T23:02:30+09:00
tags: [ "competitive", "writeup", "atcoder", "s8pc", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/s8pc-2/tasks/s8pc_2_c" ]
---

# square869120Contest #2 C - 何通りの分割方法がある？

## solution

DP。

$i$番目の文字までを使って総和が$j$になるような分割の数$dp\_{i,j}$を更新すればよい。
いい感じに実装する。
計算量は$O((\log D)^{\log N})$あたりだろうか。

## implementation

```
        repeat_from (l, max(0,r-int(2+d.length())), r)
```

のあたりのバグで悩んだ。

``` c++
#include <iostream>
#include <vector>
#include <unordered_map>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
using namespace std;
const int mod = 1e9+7;
int main() {
    string n, d; cin >> n >> d;
    int di = stoi(d);
    vector<unordered_map<int,int> > dp(n.length()+1);
    dp[0][0] = 1;
    repeat_from (r, 1, n.length()+1) {
        repeat_from (l, max(0,r-int(2+d.length())), r) {
            for (auto p : dp[l]) {
                int suml, cnt; tie(suml, cnt) = p;
                int sumr = suml + stoi(n.substr(l,r-l));
                if (di < sumr) continue;
                dp[r][sumr] += cnt;
                dp[r][sumr] %= mod;
            }
        }
    }
    int ans = 0;
    for (auto p : dp[n.length()]) {
        int sum, cnt; tie(sum, cnt) = p;
        ans += cnt;
        ans %= mod;
    }
    cout << ans << endl;
    return 0;
}
```

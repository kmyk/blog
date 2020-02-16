---
layout: post
alias: "/blog/2016/06/20/abc-040-c/"
date: 2016-06-20T00:56:19+09:00
tags: [ "competitive", "writeup", "abc", "atcoder", "graph", "dp", "dag" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc040/tasks/abc040_c" ]
---

# AtCoder Beginner Contest 040 C - 柱柱柱柱柱

分かりやすいDP。DPとはDAG上の最短路だ、みたいなのが実感できて好きです。

## solution

DP。$O(N)$。

## implementation

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
using namespace std;
int main() {
    int n; cin >> n;
    vector<int> a(n); repeat (i,n) cin >> a[i];
    vector<int> dp(n);
    dp[0] = 0;
    dp[1] = abs(a[1] - a[0]);
    repeat_from (i,2,n) {
        dp[i] = min(dp[i-1] + abs(a[i] - a[i-1]),
                    dp[i-2] + abs(a[i] - a[i-2]));
    }
    cout << dp[n-1] << endl;
    return 0;
}
```

---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/107/
  - /blog/2017/01/11/yuki-107/
date: "2017-01-11T15:06:42+09:00"
tags: [ "competitive", "writeup", "yukicoder", "dp", "bit-dp" ]
"target_url": [ "http://yukicoder.me/problems/102" ]
---

# Yukicoder No.107 モンスター

## solution

bit DP。体力の上限は状態から一意に定まる。$O(2^N N)$。

## implementation

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;
template <class T> void setmax(T & a, T const & b) { if (a < b) a = b; }
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }
const int inf = 1e9+7;
int main() {
    int n; cin >> n;
    vector<int> d(n); repeat (i,n) cin >> d[i];
    int mask = 0; repeat (i,n) if (d[i] < 0) mask |= 1<<i;
    vector<int> dp(1<<n, - inf);
    dp[0] = 100;
    repeat (s,1<<n) {
        repeat (i,n) if (s&(1<<i)) {
            int t = s&~(1<<i);
            if (dp[t] + d[i] > 0) {
                setmax(dp[s], dp[t] + d[i]);
            }
        }
        int upper = 100 * (1 + __builtin_popcount(s & mask));
        setmin(dp[s], upper);
    }
    cout << max(0, dp[(1<<n)-1]) << endl;
    return 0;
}
```

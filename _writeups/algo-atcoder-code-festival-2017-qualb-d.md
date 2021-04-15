---
layout: post
redirect_from:
  - /writeup/algo/atcoder/code-festival-2017-qualb-d/
  - /blog/2017/11/10/code-festival-2017-qualb-d/
date: "2017-11-10T23:55:46+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/code-festival-2017-qualb/tasks/code_festival_2017_qualb_d" ]
---

# CODE FESTIVAL 2017 qual B: D - 101 to 010

## 感想

解けず。連続する`1`を数えて数列に変形するのは必須だと思ってその方向ばかり考えていたが、そうだとすると実装が面倒になりすぎるので完全に失敗だった。

## solution

連鎖的に操作をするとき`111...11101`あるいは`10111...111`の形を`000...00010`などにできる。
そのようなものだけ見ればよいので、`111...11101`と`10111...111`の形の部分文字列を関係としてDP。
愚直にやると$O(N^2)$だが、形が制限されているので前回の端を覚えておくなどすれば$O(N)$。

## implementation

``` c++
#include <algorithm>
#include <iostream>
#include <vector>
#define repeat_reverse(i, n) for (int i = (n)-1; (i) >= 0; --(i))
#define whole(x) begin(x), end(x)
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }

int solve(int n, string const & s) {
    vector<int> dp(n + 1);
    int r = n;
    repeat_reverse (l, n) {
        dp[l] = dp[l + 1];
        if (l + 2 < n and s[l + 2] == '0') {
            r = l + 2;
        }
        if (s[l] == '1') {
            if (s[l + 1] == '0') {
                if (s[r - 1] == '1') {
                    setmax(dp[l], dp[r] + r - l - 2);
                    if (s[r - 2] == '1') {
                        setmax(dp[l], dp[r - 1] + (r - 1) - l - 2);
                    }
                }
            } else {
                if (r + 1 < n and s[r + 1] == '1') {
                    setmax(dp[l], dp[r + 2] + (r + 2) - l - 2);
                }
            }
        }
    }
    return *max_element(whole(dp));
}

int main() {
    int n; string s; cin >> n >> s;
    cout << solve(n, s) << endl;
    return 0;
}
```

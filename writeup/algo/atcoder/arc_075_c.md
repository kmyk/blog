---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-075-c/
  - /blog/2017/06/03/arc-075-c/
date: "2017-06-03T22:57:58+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc075/tasks/arc075_a" ]
---

# AtCoder Regular Contest 075: C - Bugged

何も考えず書いたがoverkillだったらしい。

## solution

DP。作れる和を全部列挙しても間に合う。$O(N \sum s\_i)$。想定-非正攻法だったみたい。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <array>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
using namespace std;
int main() {
    int n; scanf("%d", &n);
    vector<int> a(n); repeat (i,n) scanf("%d", &a[i]);
    array<bool, 10001> dp = {};
    dp[0] = true;
    repeat (i, n) {
        repeat_reverse (j, 10001) {
            if (dp[j] and j + a[i] < 10001) {
                dp[j + a[i]] = true;
            }
        }
    }
    int result = 0;
    repeat (i, 10001) {
        if (dp[i] and i % 10 != 0) {
            result = i;
        }
    }
    printf("%d\n", result);
    return 0;
}
```

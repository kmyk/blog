---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_067_f/
  - /writeup/algo/atcoder/arc-067-f/
  - /blog/2017/01/15/arc-067-f/
date: "2017-01-15T23:28:43+09:00"
tags: [ "competitive", "writeup", "arc", "atcoder", "optimization" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc067/tasks/arc067_d" ]
---

# AtCoder Regular Contest 067: F - Yakiniku Restaurants

だめ。こういうのを通せると気持ちいいんだけどなあ。

## solution

$O(N^2M)$で間に合う。clangの自動vector化とかが効いてるらしい。
gccも`#pragma`を書けばしてくれるが、clangより遅い。

## implementation

``` c++
#include <cstdio>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
using ll = long long;
using namespace std;

int n, m;
int a[5003];
ll a_acc[5003];
int b[5003][203];
int b_best[203];
int main() {
    scanf("%d%d", &n, &m);
    repeat (i,n-1) scanf("%d", &a[i]);
    repeat (i,n-1) a_acc[i+1] = a_acc[i] + a[i];
    repeat (i,n) repeat (j,m) scanf("%d", &b[i][j]);
    ll ans = 0;
    repeat (l,n) {
        repeat (j,m) b_best[j] = 0;
        ll b_acc = 0;
        repeat_from (r,l,n) { // [l,r]
            repeat (j,m) {
                if (b_best[j] < b[r][j]) {
                    b_acc += - b_best[j] + b[r][j];
                    b_best[j] = b[r][j];
                }
            }
            ans = max(ans, b_acc - (a_acc[r] - a_acc[l]));
        }
    }
    printf("%lld\n", ans);
    return 0;
}
```

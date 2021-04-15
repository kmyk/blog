---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_070_c/
  - /writeup/algo/atcoder/arc-070-c/
  - /blog/2017/05/02/arc-070-c/
date: "2017-05-02T22:27:59+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc070/tasks/arc070_a" ]
---

# AtCoder Regular Contest 070: C - Go Home

## solution

$x \le \sum\_{n \le t} n$な最小の$t$が答え。愚直にやっても$O(\sqrt{X})$。

時刻と移動可能な座標を表にすると以下のように。

```
t: x
0: 0
1: 0 1
2: 0 1 2 3
3: 0 1 2 3 4 5 6
4: 0 1 2 3 4 5 6 7 8 9 10
5: 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
```

## implementation

``` c
#include <stdio.h>
int main() {
    int x; scanf("%d", &x);
    int t = 0;
    while (t*(t+1)/2 < x) ++ t;
    printf("%d\n", t);
    return 0;
}
```

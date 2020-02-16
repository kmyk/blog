---
layout: post
redirect_from:
  - /blog/2017/11/27/cf17-relay-b/
date: "2017-11-27T17:58:07+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "team-relay", "tree" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf17-relay-open/tasks/relay2_b" ]
---

# Code Festival Team Relay: B - Evergrowing Tree

## solution

$O(Q \cdot (\log v\_i + \log w\_i))$。
毎回対数時間かけて合流するまで登っていけばよい。親を求めるのはいい感じにして$N$で割る。

$n = 1$の場合に注意。

## implementation

``` c++
#include <algorithm>
#include <cstdio>
using namespace std;
int main() {
    int n, q; scanf("%d%d", &n, &q);
    while (q --) {
        int i, j; scanf("%d%d", &i, &j); -- i; -- j;
        if (n == 1) {
            i = j = min(i, j);
        } else {
            while (i != j) {
                ((i > j ? i : j) -= 1) /= n;
            }
        }
        printf("%d\n", i + 1);
    }
    return 0;
}
```

---
layout: post
redirect_from:
  - /writeup/algo/csacademy/72-e/
  - /writeup/algo/cs-academy/72-e/
  - /blog/2018/03/08/csa-72-e/
date: "2018-03-08T12:04:36+09:00"
tags: [ "competitive", "writeup", "csa", "query", "interval", "graph" ]
"target_url": [ "https://csacademy.com/contest/round-72/task/enemy/" ]
---

# CS Academy Round #72. Line Enemies

## solution

距離は高々$3$。$O(Q \log Q)$。

-   同じ区間のとき$0$
-   ふたつが交わったないとき$1$
-   どちらとも交わらない区間があるとき$2$
-   $[L\_1, R\_1]$とだけ交わる区間および$[L\_1, R\_1]$とだけ交わる区間があるとき$3$
-   それ以外は$-1$

## implementation

``` c++
#include <bits/stdc++.h>
using namespace std;

int main() {
    // prepare
    set<pair<int, int> > s;
    map<int, int> lcnt, rcnt;

    // query
    int query; scanf("%d", &query);
    while (query --) {
        int type; scanf("%d", &type);
        if (type == 1) {
            int l, r; scanf("%d%d", &l, &r); -- l;
            s.emplace(l, r);
            lcnt[l] += 1;
            rcnt[r] += 1;
        } else if (type == 2) {
            int l, r; scanf("%d%d", &l, &r); -- l;
            s.erase(make_pair(l, r));
            if (not (lcnt[l] -= 1)) lcnt.erase(l);
            if (not (rcnt[r] -= 1)) rcnt.erase(r);
        } else if (type == 3) {
            int l1, r1; scanf("%d%d", &l1, &r1); -- l1;
            int l2, r2; scanf("%d%d", &l2, &r2); -- l2;
            bool included = (l1 <= l2 and r2 <= r1) or (l2 <= l1 and r1 <= r2);
            int lmax = lcnt.rbegin()->first;
            int rmin = rcnt. begin()->first;
            int result;
            if (l1 == l2 and r1 == r2) {
                result = 0;
            } else if (r1 <= l2 or r2 <= l1) {
                result = 1;
            } else if (max(r1, r2) <= lmax or rmin <= min(l1, l2)) {
                result = 2;
            } else if (not included and rmin <= max(l1, l2) and rmin <= lmax and min(r1, r2) <= lmax) {
                result = 3;
            } else {
                result = -1;
            }
            printf("%d\n", result);
        } else {
            assert (false);
        }
    }
    return 0;
}
```

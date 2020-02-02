---
layout: post
alias: "/blog/2017/01/22/fhc-2017-round2-a/"
date: "2017-01-22T07:00:06+09:00"
title: "Facebook Hacker Cup 2017 Round 2: A - Subtle Sabotage"
tags: [ "competitive", "writeup", "facebook-hacker-cup" ]
"target_url": [ "https://www.facebook.com/hackercup/problem/371325719893664/" ]
---

## solution

$O(1)$.
Mainly, there are $2$ patterns to achieve the purpose.
One uses a corner, and one uses an edge and the opposite edge. See below.

```
+-+----------+
| #          |
|   #        |
+###         |
|            |
|            |
+------------+
```

```
+--------+---+
|        #   |
|          # |
|          # |
|          # |
|          # |
+----------+-+
```

But for one using a corner, take care that the case of $K = 1$ and the others is a little bit different.


```
+-++---------+
| ##         |
| ##         |
|    ##      |
+##@@##      |
+##@@        |
+------------+
```

## implementation

``` c++
#include <iostream>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }
const int inf = 1e9+7;
int solve(int h, int w, int k) {
    if (h > w) swap(h, w);
    int ans = inf;
    if (k+1 <= h and 2*k+3 <= w) setmin(ans, (h + k-1) / k);
    if (k == 1 and h >= 3 and w >= 5) setmin(ans, 5);
    if (k >= 2 and 2*k+1 <= h and 3*k+1 <= w) setmin(ans, 4);
    return ans == inf ? -1 : ans;
}
int main() {
    int t; cin >> t;
    repeat (i,t) {
        int n, m, k; cin >> n >> m >> k;
        cout << "Case #" << i+1 << ": " << solve(n, m, k) << endl;
    }
    return 0;
}
```

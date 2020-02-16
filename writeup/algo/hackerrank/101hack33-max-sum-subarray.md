---
layout: post
alias: "/blog/2016/01/21/hackerrank-101hack33-max-sum-subarray/"
date: 2016-01-21T21:32:51+09:00
tags: [ "competitive", "writeup", "hackerrank" ]
---

# Hackerrank 101 Hack Jan 2016 Max-Sum-Subarray

## [Max-Sum-Subarray](https://www.hackerrank.com/contests/101hack33/challenges/max-sum-subarray)

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
int main() {
    int n; cin >> n;
    vector<int> a(n); repeat (i,n) cin >> a[i];
    int ans = 0;
    int prv = 0;
    repeat (i,n) {
        if (a[i] == 0) {
            prv = 0;
        } else {
            prv = a[i] + max(prv, 0);
            ans = max(ans, prv);
        }
    }
    cout << ans << endl;
    return 0;
}
```

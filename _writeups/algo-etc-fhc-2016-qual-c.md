---
layout: post
redirect_from:
  - /writeup/algo/etc/fhc-2016-qual-c/
  - /blog/2016/01/11/fhc-2016-qual-c/
date: 2016-01-12 9:00:00 +0900
tags: [ "competitive", "writeup", "facebook-hacker-cup", "shakutori-hou" ]
---

# Facebook Hacker Cup 2016 Qualification Round The Price is Correct

## [The Price is Correct](https://www.facebook.com/hackercup/problem/881509321917182/)

### 問題

数列$a$と整数$p$が与えられる。
数列$a$の区間で、区間中の数の和が$p$以下であるものの数を答えよ。

### 解法

しゃくとり法。
$O(N)$。

### 実装

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
void solve() {
    int n; ll p; cin >> n >> p;
    vector<ll> b(n); repeat (i,n) cin >> b[i];
    ll ans = 0;
    ll acc = 0;
    int l = 0;
    repeat (r,n) { // [l,r]
        acc += b[r];
        while (p < acc) acc -= b[l ++];
        ans += r-l+1;
    }
    cout << ans << endl;
}
int main() {
    int testcases; cin >> testcases;
    repeat (testcase, testcases) {
        cout << "Case #" << testcase+1 << ": ";
        solve();
    }
    return 0;
}
```

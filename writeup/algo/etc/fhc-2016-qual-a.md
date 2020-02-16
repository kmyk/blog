---
layout: post
redirect_from:
  - /blog/2016/01/11/fhc-2016-qual-a/
date: 2016-01-12 9:00:00 +0900
tags: [ "competitive", "writeup", "facebook-hacker-cup" ]
---

# Facebook Hacker Cup 2016 Qualification Round Boomerang Constellations

## [Boomerang Constellations](https://www.facebook.com/hackercup/problem/910374079035613/)

### 問題

座標が複数個与えられる。
異なる座標3つからなる組$(p, { q, r })$で、$\|q - p\| = \|r - p\|$を満たすものの数を答えよ。

### 解法

$N \le 2000$であるので、$O(N^2)$でよい。
中心となる座標$p$を固定し、他の座標全てに関して距離を計算すれば、それぞれの距離$d$に関して、$p$から距離$d$離れた座標が$i$個あるとき、${}\_iC_2$個の組がある。

### 実装

``` c++
#include <iostream>
#include <vector>
#include <unordered_map>
#include <tuple>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
struct point_t { int y, x; };
ll sq(ll x) { return x*x; }
ll squared_distance(point_t a, point_t b) { return sq(a.y-b.y) + sq(a.x-b.x); }
void solve() {
    int n; cin >> n;
    vector<point_t> p(n); repeat (i,n) cin >> p[i].x >> p[i].y;
    ll ans = 0;
    repeat (i,n) {
        unordered_map<ll,int> s;
        repeat (j,n) {
            s[squared_distance(p[i], p[j])] += 1;
        }
        for (auto it : s) {
            ll dist, cnt; tie(dist, cnt) = it;
            if (dist == 0) assert (cnt == 1);
            ans += cnt * (cnt - 1) / 2;
        }
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

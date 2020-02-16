---
layout: post
redirect_from:
  - /blog/2016/01/24/fhc-2016-round2-c/
date: 2016-01-24T06:02:47+09:00
tags: [ "competitive", "writeup", "facebook-hacker-cup", "stack" ]
---

# Facebook Hacker Cup 2016 Round 2 Snakes and Ladders

ケース数$T \le 50$、はしごの数$N \le 200000$、制限時間$360$秒なので$O(n^2)$は怪しい。
しかし、ねぼけて$O(n^2)$で挑んだら通ってしまった。

Tシャツ貰えました。

## [Snakes and Ladders](https://www.facebook.com/hackercup/problem/1640119959603837/)

### 問題

はしごが$n$個ある。$i$番目のはしごは位置$x_i$にあって高さは$h_i$である。複数のはしごが同じ位置にあることはない。
以下のような条件を満たすはしごの組$a,b$全てについて、費用が$\|b - a\|^2$かかる。

-   高さが同じ。$h_a = h_b$。
-   間にそれらより真に高いはしごがない。$\forall c. ( x_a \lt x_c \lt x_b \to h_c \le \min \\{ h_a, h_b \\} )$。

はしごの位置が与えられるので、費用を答えよ。

### 解法

stackを使って愚直にやれば$O(n^2)$はできる。

想定解法は$O(n)$のようだ。
$(x_a - x_b)^2 = x_a^2 - 2x_ax_b + x_b^2$であるので、
総和に関しても$\Sigma_i (x_i - x_b)^2 = \Sigma_i x_i^2 - (\Sigma_i x_i) \dot 2x_b + x_b^2$である。
$\Sigma_i x_i^2$と$\Sigma_i x_i$を持ちながら同じことをすればよい。

### 実装

``` c++
#include <iostream>
#include <algorithm>
#include <vector>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
struct ladder_t { ll x, h; };
bool operator < (ladder_t a, ladder_t b) { return a.x < b.x; }
const ll mod = 1e9+7;
void solve() {
    int n; cin >> n;
    vector<ladder_t> ls(n);
    repeat (i,n) cin >> ls[i].x >> ls[i].h;
    sort(ls.begin(), ls.end());
    ll ans = 0;
    vector<ladder_t> stk;
    for (auto l : ls) {
        while (not stk.empty() and stk.back().h < l.h) stk.pop_back();
        for (auto it = stk.rbegin(); it != stk.rend() and it->h == l.h; ++ it) {
            ll dx = l.x - it->x;
            ans = (ans +  dx*dx % mod) % mod;
        }
        stk.push_back(l);
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

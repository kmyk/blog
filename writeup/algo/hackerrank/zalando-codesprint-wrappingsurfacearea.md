---
layout: post
redirect_from:
  - /writeup/algo/hackerrank/zalando-codesprint-wrappingsurfacearea/
  - /blog/2016/06/05/hackerrank-zalando-codesprint-wrappingsurfacearea/
date: 2016-06-05T19:17:30+09:00
tags: [ "competitive", "writeup", "hackerrank", "exhaustive-search" ]
"target_url": [ "https://www.hackerrank.com/contests/zalando-codesprint/challenges/wrappingsurfacearea" ]
---

# HackerRank Zalando CodeSprint: Minimal Wrapping Surface Area

何故か`const ll inf = 1e8;`と書いてしまっていたためにWAが生まれた。

## problem

$W \times H \times L$の箱が$N$個ある。
これを適当に並べたときの、それら全体のbounding boxの表面積の最小値を答えよ。
ただし、箱やbounding boxは全て軸並行で、回転はできないものとする。

## solution

Exhaustive search the $N \times N \times N$ space with trivial branching.

## implementation

``` c++
#include <iostream>
#include <cassert>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
typedef long long ll;
template <class T> bool setmin(T & l, T const & r) { if (not (r < l)) return false; l = r; return true; }
using namespace std;
const ll inf = 1e18+9;
int main() {
    int n; cin >> n;
    int x, y, z; cin >> x >> y >> z;
    ll ans = inf;
    repeat_from (i,1,n+1) {
        repeat_from (j,1,n+1) {
            repeat_from (k,1,n+1) {
                if (i*j*k < n) continue;
                ll nx = x * i;
                ll ny = y * j;
                ll nz = z * k;
                setmin(ans, 2 * (nx * ny + ny * nz + nz * nx));
            }
        }
    }
    cout << ans << endl;
    return 0;
}
```

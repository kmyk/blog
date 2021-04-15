---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_001_d/
  - /writeup/algo/atcoder/arc-001-d/
  - /blog/2016/05/26/arc-001-d/
date: 2016-05-26T04:43:22+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "geometry" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc001/tasks/arc001_4" ]
---

# AtCoder Regular Contest 001 D - レースゲーム

TLEが厳しい幾何はだめ。

## solution

貪欲な感じで道を構成していく。速い$O(N^2)$。

始点から始めて頂点を追加していくことで最短路を構成していく。
最後に追加した頂点を$P$とする。
$P$に$y$座標が近い順に見ていって、左の壁と右の壁が($P$から見て)始めて重なる場所を探す。
重なっている壁の上側を作っている頂点$Q$を最短路を構成する頂点として採用する。
これを、終点に達するまで繰り返せばよい。

## implementation

`atan2`を使うとTLEる。2次元外積を使えば通った。

``` c++
#include <iostream>
#include <vector>
#include <functional>
#include <cmath>
#include <cstdio>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
typedef long long ll;
using namespace std;
 
int main() {
    int n; cin >> n;
    int start, goal; cin >> start >> goal;
    vector<int> l(n+1), r(n+1); repeat (i,n+1) cin >> l[i] >> r[i];
    l[0] = r[0] = start;
    l[n] = r[n] = goal;
    double acc = 0;
    int y = 0, x = start;
    auto cmp = [&](int ay, int ax, int by, int bx) {
        return (ax - x) *(ll) (by - y) - (ay - y) *(ll) (bx - x) < 0;
    };
    while (y < n) {
        int ly = y, ry = y;
        int lx = x-1, rx = x+1;
        repeat_from (ny,y+1,n+1) {
            if (cmp(ny, r[ny], ly, lx) and ly != y) { acc += hypot(ly - y, l[ly] - x); y = ly; x = l[ly]; goto next; }
            if (cmp(ry, rx, ny, l[ny]) and ry != y) { acc += hypot(ry - y, r[ry] - x); y = ry; x = r[ry]; goto next; }
            if (cmp(ny, r[ny], ry, rx)) { ry = ny; rx = r[ny]; }
            if (cmp(ly, lx, ny, l[ny])) { ly = ny; lx = l[ny]; }
        }
        acc += hypot(n - y, goal - x); y = n; x = goal;
next:;
    };
    printf("%.14f\n", acc);
    return 0;
}
```

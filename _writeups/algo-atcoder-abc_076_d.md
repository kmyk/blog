---
layout: post
redirect_from:
  - /writeup/algo/atcoder/abc_076_d/
  - /writeup/algo/atcoder/abc-076-d/
  - /blog/2017/12/08/abc-076-d/
date: "2017-12-08T07:24:14+09:00"
tags: [ "competitive", "writeup", "atcoder", "abc", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc076/tasks/abc076_d" ]
---

# AtCoder Beginner Contest 076: D - AtCoder Express

全部perlで提出したかったのですが、perlでは間に合いませんでした (<https://beta.atcoder.jp/contests/abc076/submissions/1721602>)

## solution

DP。$O(\sum t\_i \cdot \max v\_i)$。

時刻$t$に速度$v$で走っているときのそれまでの走行距離の最大値を$\mathrm{dp}(t, v)$とすればよい。
ただし$t \in \mathbb{N}$だと粗すぎてだめで、$0.5$刻みで計算しなければならない。

## implementation

``` c++
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i, m, n) for (int i = (m); (i) < int(n); ++(i))
#define whole(x) begin(x), end(x)
using namespace std;

int main() {
    int n; scanf("%d", &n);
    vector<int> t(n); repeat (i, n) scanf("%d", &t[i]);
    vector<int> v(n); repeat (i, n) scanf("%d", &v[i]);
    const int max_v = *max_element(whole(v));
    constexpr int zoom = 2;
    vector<double> cur(zoom * max_v + 3, - INFINITY);
    vector<double> prv(zoom * max_v + 3, - INFINITY);
    cur[0] = 0;
    repeat (i, n) {
        fill(cur.begin() + (zoom * v[i] + 1), cur.end(), - INFINITY);
        fill(prv.begin() + (zoom * v[i] + 1), prv.end(), - INFINITY);
        repeat (tick, zoom * t[i]) {
            cur.swap(prv);
            cur[0] = max(prv[0], prv[1] + 0.5 / zoom);
            repeat_from (a, 1, zoom * v[i] + 1) {
                cur[a] = max({ prv[a - 1] - 0.5 / zoom, prv[a], prv[a + 1] + 0.5 / zoom }) + a /(double) (zoom * zoom);
            }
        }
    }
    printf("%.12lf\n", cur[0]);
    return 0;
}
```

---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_067_d/
  - /writeup/algo/atcoder/arc-067-d/
  - /blog/2017/01/15/arc-067-d/
date: "2017-01-15T22:49:43+09:00"
tags: [ "competitive", "writeup", "arc", "atcoder" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc067/tasks/arc067_b" ]
---

# AtCoder Regular Contest 067: D - Walk and Teleport

実装結果が短くて驚く。

## solution

テレポートは東に$1$つ分しかしないとしてよい。$O(N)$。

西へ向かって歩くことがあるかと考えると、東へ大きくテレポートして戻ってくるとき。
そうした場合、西へ歩き終わった後再度東へ大きくテレポートする。
これは西へ向かって歩く部分の歩く向きを反転させてよく、常に東へ歩くようにできる。必然的にテレポートの距離は$1$。

## implementation

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;
int main() {
    int n, a, b; cin >> n >> a >> b;
    vector<int> x(n); repeat (i,n) cin >> x[i];
    ll acc = 0;
    repeat (i,n-1) acc += min<ll>(b, a *(ll) (x[i+1] - x[i]));
    cout << acc << endl;
    return 0;
}
```

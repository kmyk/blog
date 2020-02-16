---
layout: post
alias: "/blog/2016/11/05/ddcc-2016-qual-b/"
date: "2016-11-05T22:26:11+09:00"
tags: [ "competitive", "writeup", "atcoder", "ddcc" ]
"target_url": [ "https://beta.atcoder.jp/contests/ddcc2016-qual/tasks/ddcc_2016_qual_b" ]
---

# DISCO presents ディスカバリーチャンネル コードコンテスト2016 予選: B - ステップカット

誤読した。問題分が長くて面倒な感じだったから適当に読んだのが原因。今年は大きい枠に入ってるのでこれでも通るしunratedだから被害はなかったが要反省。

## solution

指定されたことを実装するだけ。三角関数の基本的な知識を使う。$O(N)$。

## implementation

``` c++
#include <cstdio>
#include <algorithm>
#include <cmath>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
int main() {
    int r, n, m; ; scanf("%d%d%d", &r, &n, &m);
    auto l = [&](int i) {
        double sine = 0 <= i and i <= n ? 1 - 2*i /(double) n : 1;
        return 2*r * sqrt(1 - pow(sine, 2));
    };
    double ans = 0;
    repeat (i, n+m) ans += max(l(i-m), l(i));
    printf("%.12lf\n", ans);
    return 0;
}
```

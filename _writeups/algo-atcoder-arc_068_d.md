---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_068_d/
  - /writeup/algo/atcoder/arc-068-d/
  - /blog/2017/05/16/arc-068-d/
date: "2017-05-16T21:32:39+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc068/tasks/arc068_b" ]
---

# AtCoder Regular Contest 068: D - Card Eater

## solution

余剰カードの枚数を$b$、それ以外のカードの枚数(つまり書かれた値の種類数)を$a$とすると答えは$a - (b \bmod 2)$。
整列するから$O(N \log N)$あるいは$O(\max A\_i)$。

値$A, B$が書かれたカードがそれぞれ複数枚あるとき、$A, A, B$あるいは$A, B, B$とすれば両方を$1$枚ずつ減らせる。
これは$A = B$でもよい。
よって、最後に$1$枚余るかどうかだけ考えればよい。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;
int main() {
    int n; scanf("%d", &n);
    vector<int> a(n); repeat (i,n) scanf("%d", &a[i]);
    whole(sort, a);
    int n_unique = whole(unique, a) - a.begin();
    int n_duplicated = n - n_unique;
    int ans = n_unique - (n_duplicated % 2 == 0 ? 0 : 1);
    printf("%d\n", ans);
    return 0;
}
```

---
layout: post
redirect_from:
  - /blog/2016/08/21/agc-003-c/
date: "2016-08-21T23:55:21+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc003/tasks/agc003_c" ]
---

# AtCoder Grand Contest 003 C - BBuBBBlesort!

## solution

元の列の偶数番目の数を集めてきたものと、整列後の列の偶数番目の数を集めてきたものを見比べる。$O(N \log N)$。

ひとつ飛ばしての交換は自由にできる。隣接するものの交換の回数を最小化したい。
列の偶数番目の数同士、奇数番目の数同士は自由に交換でき、その間で整列もできるので、偶数奇数が変化しないといけない数の数が答えである。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#include <unordered_set>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) y) { return (f)(begin(y), end(y), ## __VA_ARGS__); })(x)
using namespace std;
int main() {
    int n; scanf("%d", &n);
    vector<int> a(n); repeat (i,n) scanf("%d", &a[i]);
    unordered_set<int> x;
    for (int i = 0; i < n; i += 2) x.insert(a[i]);
    whole(sort, a);
    int ans = 0;
    for (int i = 1; i < n; i += 2) ans += x.count(a[i]);
    printf("%d\n", ans);
    return 0;
}
```

---
layout: post
redirect_from:
  - /writeup/algo/atcoder/abc_041_c/
  - /writeup/algo/atcoder/abc-041-c/
  - /blog/2016/07/04/abc-041-c/
date: "2016-07-04T05:28:18+09:00"
tags: [ "competitive", "writeup", "atcoder", "abc" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc041/tasks/abc041_c" ]
---

# AtCoder Beginner Contest 041 C - 背の順

普段より簡単

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) y) { return (f)(begin(y), end(y), ## __VA_ARGS__); })(x)
using namespace std;
int main() {
    int n; scanf("%d", &n);
    vector<int> a(n); repeat (i,n) scanf("%d", &a[i]);
    vector<int> xs(n); whole(iota, xs, 0);
    whole(sort, xs, [&](int i, int j) { return a[i] > a[j]; });
    for (int i : xs) printf("%d\n", i+1);
    return 0;
}
```

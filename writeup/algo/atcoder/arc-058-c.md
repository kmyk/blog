---
layout: post
redirect_from:
  - /blog/2016/07/23/arc-058-c/
date: "2016-07-23T23:10:42+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc058/tasks/arc058_a" ]
---

# AtCoder Regular Contest 058 C - こだわり者いろはちゃん / Iroha's Obsession

なんだかうだうだやってたら少し時間がかかったが、冷静になれば完全にやるだけ。

## solution

愚直に試せばよい。$O(N\log N)$。

$N$の桁数$+1$までの中に必ず答えはある。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#include <string>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) y) { return (f)(begin(y), end(y), ## __VA_ARGS__); })(x)
using namespace std;
int main() {
    int n, k; scanf("%d%d", &n, &k);
    vector<char> d(k); repeat (i,k) scanf(" %c", &d[i]);
    int i = n;
    for (; ; ++ i) {
        string s = to_string(i);
        bool invalid = false;
        for (char c : s) {
            if (whole(count, d, c)) {
                invalid = true;
                break;
            }
        }
        if (not invalid) {
            break;
        }
    }
    printf("%d\n", i);
    return 0;
}
```

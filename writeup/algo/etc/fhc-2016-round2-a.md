---
layout: post
redirect_from:
  - /blog/2016/01/24/fhc-2016-round2-a/
date: 2016-01-24T06:02:35+09:00
tags: [ "competitive", "writeup", "facebook-hacker-cup", "greedy" ]
---

# Facebook Hacker Cup 2016 Round 2 Boomerang Decoration

## [Boomerang Decoration](https://www.facebook.com/hackercup/problem/424794494381569/)

### 問題

文字列$a,b$が与えられる。
prefixとsuffixをそれぞれ何らかの文字で塗り潰す変換$a = (a_1, a_2, \dots, a_n) \to a' = (x, x, x, \dots, x, a_i, a\_{i+1}, a\_{i+2}, \dots, a\_{j-1}, a_j, y, y, y, \dots y)$ができる。
これを繰り返し、文字列$a$を$b$に変換するとき、変換は最小で何回必要か。

### 解法

貪欲に両側から塗っていって、完成したら終了。$O(n)$。

### 実装

実験したところ`string.operator !=`でも間に合うようなのでさぼった。$O(n^2)$。

``` c++
#include <iostream>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
void solve() {
    int n; string a, b; cin >> n >> a >> b;
    int ans = 0;
    for (int i = 0, j = n-1; a != b; ++ ans) {
        int pi = i; while (i <  n and b[i] == b[pi]) { a[i] = b[i]; ++ i; }
        int pj = j; while (j >= 0 and b[j] == b[pj]) { a[j] = b[j]; -- j; }
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

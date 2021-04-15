---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_088_d/
  - /writeup/algo/atcoder/arc-088-d/
  - /blog/2018/01/03/arc-088-d/
date: "2018-01-03T23:45:58+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc088/tasks/arc088_b" ]
---

# AtCoder Regular Contest 088: D - Wide Flip

そう難しくはないはずだがしばらく悩んだ。なぜなのか。

## solution

答え$K = \max \\{ k \le \|S\| \mid S\_{n - k} = S\_{n - k + 1} = \dots = S\_{k - 1} \\}$。$O(\|S\|)$。

区間$[l, r]$と$[l, r + 1]$をそれぞれ反転することで区間$[r + 1, r + 1]$ (つまり$S\_{r + 1}$だけ) を反転することができる。
$K$を固定すると両端から$\|S\| - K$文字は自由に反転でき、中央の部分は一様に反転することしかできない。
これにより上の式が出る。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using namespace std;

int main() {
    // input
    string s; cin >> s;
    // solve
    int n = s.length();
    vector<int> acc(n + 1);
    REP (i, n) acc[i + 1] = acc[i] + (s[i] - '0');
    int k = n;
    while (acc[n - k] - acc[k] != 0 and
           acc[n - k] - acc[k] != n - 2 * k) {
        -- k;
    }
    // output
    printf("%d\n", k);
    return 0;
}
```

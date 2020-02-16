---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-053-b/
  - /blog/2016/05/14/arc-053-b/
date: 2016-05-14T23:02:59+09:00
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc053/tasks/arc053_b" ]
---

# AtCoder Regular Contest 053 B - 回文分割

致命的な勘違いにより解けず。形式化のしすぎ。

各文字の出現回数$f_c$を考えた後、これに関する(正しい答えは導かない)整数計画問題になぜか帰着させてしまい、それを解こうとし続けてしまった。

## solution

$O(N)$で頻度を数えて$O(1)$。

最終的にいくつの回文に分割することになるか考える。
$S$中に偶数回出現する文字に関して、これは回文の数を増やすことはない。
$S$中に奇数回出現する文字に関して、これはその文字を中心とした回文をひとつ要求する。
$S$中に奇数回出現する文字の種類数を$K$として、$\max \\{ 1, K \\}$個の回文になる。

$K = 0$は自明である。$K \ge 1$とする。
回文の個数は$K$個で、それぞれ中心に$f_c = 1 \pmod 2$なる文字$c$がある。
これらを残りの$P = \frac{N - K}{2}$組の文字らで挟んでいく。
よって$ans = 1 + 2 \cdot \lfloor \frac{P}{K} \rfloor$。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <array>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
int main() {
    string s; cin >> s;
    array<int,26> freq = {};
    for (char c : s) freq[c - 'a'] += 1;
    int k = 0;
    repeat (i,26) if (freq[i]) {
        if (freq[i] % 2 == 1) {
            k += 1;
        }
    }
    int n = s.length();
    int ans = k == 0
        ? n
        : 1 + (n - k) / 2 / k * 2;
    cout << ans << endl;
    return 0;
}
```

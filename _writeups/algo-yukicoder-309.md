---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/309/
  - /blog/2015/12/03/yuki-309/
date: 2015-12-03T00:56:54+09:00
tags: [ "yukicoder", "competitive", "writeup", "dp", "probability", "expected-value" ]
---

# Yukicoder No.309 シャイな人たち (1)

[Advent Calendar Contest Advent Calendar 2015](http://www.adventar.org/calendars/912)の2日目。

独立でない事象について上手に期待値を求める問題。
私にとって難しめであったがなんとか自力で解けた。
想定解法は$O((R+C)4^C)$だったらしいが、c++なので$O(RC4^C)$で通せてしまった。

<!-- more -->

## [No.309 シャイな人たち (1)](http://yukicoder.me/problems/846)

### 問題

$H\times W$の形に人々が並んでいる。
この人々に向かって質問がなされ、分かる人は挙手を求められる。
各々の人は確率$p\_{i,j}$で解答を知っている。人々はシャイなので、解答を知っていて、自分の真横あるいは目前の3人の内$S\_{i,j}$人以上が手を挙げていれば、自分も手を挙げる。
手を挙げる人数の期待値を求めよ。

### 解法

人々は、前から後ろへ一方通行で影響し、左右では相互に影響し合う。
また、ある行はその直前の行の挙手の状況にしか影響されない。
このため、前の行から順々に決定していくことができる。

特に、ある行の挙手状況は、その行の知識の状況と直前の行の挙手状況によってのみ決まる。
したがって、`dp[行][挙手状況] = 確率`というdpを行えばよい。
更新のときは、全ての知識の状況に関して試すことが必要。
計算量は、`行数 * その行の知識状況 * 前行の挙手状況 * 列数`で$O(RC 4^C)$。
ただしここで挙手状況などと言ってるのは、各々の人が手を挙げているかどうかの$C {\rm bit}$の情報のこと。

### 反省

-   知識の状況と挙手の状況が異なるという認識がなかった。寝不足だろうか。
    -   例えば$s = (0~4)$であるような行に関して、共に挙手しない場合とは、両方答えを知らない場合、右側の人のみ知っている場合の2通りあり、挙手の状況と知識の状況は一致しない。

### 実装

``` c++
#include <iostream>
#include <cstdio>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
using namespace std;
inline bool at(int s, int i) {
    return s & (1 << i);
}
int main() {
    int h, w; cin >> h >> w;
    vector<vector<double> > p(h, vector<double>(w)); repeat (y,h) repeat (x,w) { cin >> p[y][x]; p[y][x] /= 100; }
    vector<vector<int   > > s(h, vector<int   >(w)); repeat (y,h) repeat (x,w)   cin >> s[y][x];
    vector<vector<double> > dp(h+1, vector<double>(1<<w)); // dp[y][hand] = probability
    dp[0][0] = 1;
    repeat (y,h) {
        repeat (knowledge,1<<w) {
            double q = 1;
            repeat (x,w) q *= at(knowledge,x) ? p[y][x] : 1 - p[y][x];
            repeat (phand,1<<w) {
                int hand = 0;
                repeat (x,w) {
                    if (s[y][x] == 0 and at(knowledge,x)) hand |= (1<<x);
                    if (s[y][x] == 1 and at(knowledge,x) and at(phand,x)) hand |= (1<<x);
                }
                repeat_from (x,1,w) {
                    if (s[y][x] == 1 and at(knowledge,x) and at(hand,x-1)) hand |= (1<<x);
                    if (s[y][x] == 2 and at(knowledge,x) and at(hand,x-1) and at(phand,x)) hand |= (1<<x);
                }
                repeat_reverse (x,w-1) {
                    if (s[y][x] == 1 and at(knowledge,x) and at(hand,x+1)) hand |= (1<<x);
                    if (s[y][x] == 2 and at(knowledge,x) and at(hand,x+1) and at(phand,x)) hand |= (1<<x);
                }
                repeat_from (x,1,w-1) {
                    if (s[y][x] == 2 and at(knowledge,x) and at(hand,x-1) and at(hand,x+1)) hand |= (1<<x);
                    if (s[y][x] == 3 and at(knowledge,x) and at(hand,x-1) and at(hand,x+1) and at(phand,x)) hand |= (1<<x);
                }
                dp[y+1][hand] += q * dp[y][phand];
            }
        }
    }
    double result = 0;
    repeat (y,h) repeat (row,1<<w) {
        result += __builtin_popcount(row) * dp[y+1][row];
    }
    printf("%.12lf\n", result);
    return 0;
}
```

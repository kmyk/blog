---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/294/
  - /blog/2016/06/07/yuki-294/
date: 2016-06-07T18:37:39+09:00
tags: [ "competitive", "writeup", "yukicoder", "exhaustive-search" ]
"target_url": [ "http://yukicoder.me/problems/743" ]
---

# Yukicoder No.294 SuperFizzBuzz

サンプルがヒント。星2と指定されていれば解けた、という人も多そう。

## solution

ある種の全探索。計算量はよく分からないが、線形ぐらいであるように見える。

$N \le 10^7$であるが、その上限である$10^7$番目のSuperFizzBuzz$5533533555333355355553555$(入出力例より)は$25$桁の数である。
SuperFizzBuzzの各桁は$3$か$5$のいずれかなので、$25$桁より小さいものの候補は$2^{25} = 3.4 \times 10^7$個である。
これらの候補は全て列挙して間に合う。
$3,5$からなる数が$3,5$で割り切れるかは各桁の総和や最下位桁を見ればよい。

## implementation

`__builtin_popcount`すればよかったぽい。

``` c++
#include <iostream>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
using namespace std;
int main() {
    int n; cin >> n;
    for (int l = 0; ; ++ l) {
        repeat (s,1<<l) {
            if (not (s & 1)) continue;
            int acc = 0;
            repeat (i,l) {
                acc += (s & (1<<i)) ? 5 : 3;
            }
            if (acc % 3 == 0) {
                n -= 1;
                if (n == 0) {
                    string t(l, '3');
                    repeat (j,l) if (s & (1<<j)) t[l-j-1] = '5';
                    cout << t << endl;
                    return 0;
                }
            }
        }
    }
}
```

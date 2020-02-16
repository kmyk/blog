---
layout: post
redirect_from:
  - /blog/2016/06/12/jag2016-domestic2-a/
date: 2016-06-12T22:30:33+09:00
tags: [ "competitive", "writeup", "icpc", "jag" ]
"target_url": [ "http://acm-icpc.aitea.net/index.php?2016%2FPractice%2F%E6%A8%A1%E6%93%AC%E5%9B%BD%E5%86%85%E4%BA%88%E9%81%B8B" ]
---

# JAG 模擬国内予選 2016: A - カレー作り

コンテスト中は友人に任せた。

## problem

For given $R_0, W_0, C, R$, answer $\min k \in \mathbb{N}$, sub to $\frac{R_0 + kR}{W_0 + w} = C$ for some $w \in \mathbb{R}, w \ge 0$.

## solution

順に全部試す。

$w \in \mathbb{R}$は適当に調整できるので、$R_0 + kR \ge CW_0$であればよい。
$R \ge 1, CW_0 \le 10000$なので下から探索すればよい。

## implementation

``` c++
#include <iostream>
using namespace std;
int main() {
    while (true) {
        int r0, w0, c, r; cin >> r0 >> w0 >> c >> r;
        if (r0 == 0 and w0 == 0 and c == 0 and r == 0) break;
        for (int i = 0; ; ++ i) {
            if (r0 + r*i >= c * w0) {
                cout << i << endl;
                break;
            }
        }
    }
    return 0;
}
```

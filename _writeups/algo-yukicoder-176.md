---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/176/
  - /blog/2016/10/04/yuki-176/
date: "2016-10-04T21:25:58+09:00"
tags: [ "competitive", "writeup", "yukicoder" ]
"target_url": [ "http://yukicoder.me/problems/no/176" ]
---

# Yukicoder No.176 2種類の切手

私とizさんとでWAを量産してる横で、後輩氏がしっかり通しておりプロみがあった。

## solution

与えられた$A, B, T$に対し、$\mathrm{ans} = \min \\{ Ax + By \mid x, y \ge 0, \; Ax + By \ge T \\}$を答える問題。
$x, y$のいずれかに対し総当たりすればよい。

$T \le 10^9$ではあるが軽いので`int`を使えば$O(\frac{T}{B})$でもなんとか間に合う。
$B$の数に関しての総当たりになるが、$A$をまったく使わない場合を漏らさないように注意する。

想定解としては、$T$を全部見るのではなく最後の$\operatorname{lcm}(A,B) + (T \bmod \operatorname{lcm}(A,B))$の分だけ見る、のようだ。

## implementation

``` c++
#include <iostream>
using namespace std;
int main() {
    int a, b, t; cin >> a >> b >> t;
    int y = (t + b-1)/b*b;
    for (int i = 0; i <= t and t < y; i += b) {
        int x = i + (t-i + a-1)/a*a;
        if (x < y) y = x;
    }
    cout << y << endl;
    return 0;
}
```

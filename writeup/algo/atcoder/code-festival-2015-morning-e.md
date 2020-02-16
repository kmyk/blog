---
layout: post
redirect_from:
  - /blog/2015/11/20/code-festival-2015-morning-e/
date: 2015-11-20T00:06:52+09:00
tags: [ "competitive", "writeup", "codefestival", "atcoder" ]
---

# CODE FESTIVAL 2015 朝プロ E - 一次元オセロ

まあ通せた。少し実装重めの方針で解いたが、実際は貪欲でよかった。

<!-- more -->

## [E - 一次元オセロ](https://beta.atcoder.jp/contests/code-festival-2015-morning-hard/tasks/cf_2015_morning_hard_a) {#e}

### 問題

一次元のオセロがある。盤は十分に長い。
今、石が盤に連続して置いてあり、その両端は白の石である。
黒番から始めて、全ての石が白になるまで繰り返す。
全体で石を引っくり返す数を最小にするように白石黒石を置いたとき、その数はいくつか。

### 解法

貪欲でよい。


あるいは、ある白石の連続が一度も引っくり返されないと決めると、全ての石に関して何回引っくり返されるかが定まる。
これは一度も引っくり返されない石の連続を中心に$\dots, -2, -1, 0, 1, 2, \dots$という形をしている。
この数列と入力$A_1, A_2, \dots, A_N$との畳み込み和を計算し、後から盤面に置かれた石の引っくり返される回数を足せば、ある白石が引っくり返されないとしたときの全体の石を引っくり返す回数が得られる。
これを全ての白石の連続に関して計算し、最小値を取ればよい。

### 実装

#### 畳み込み

``` python
#!/usr/bin/env python3
def nc2(n):
    return max(0, (n * (n - 1)) // 2)
n = int(input())
a = list(map(int,input().split()))
acc = [0] * (n + 1)
for i in range(n):
    acc[i+1] = acc[i] + a[i]
it = 0
for i in range(n):
    it += a[i] * i
result = it + nc2(n-1)
for i in range(1,n):
    it += acc[i] - (acc[n] - acc[i])
    if i % 2 == 0:
        result = min(result, it + nc2(i) + nc2(n-i-1))
print(result)
```

#### 貪欲

``` c++
#include <iostream>
#include <vector>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
typedef long long ll;
using namespace std;
int main() {
int n; cin >> n;
vector<ll> a(n); repeat (i,n) cin >> a[i];
ll acc = 0;
int i = 0, j = n-1;
while (i != j) {
    ll l = 1 + 2*a[i] + a[i+1];
    ll r = 1 + 2*a[j] + a[j-1];
    if (l < r) {
        acc += l;
        a[i+2] += 2 + a[i] + a[i+1];
        i += 2;
    } else {
        acc += r;
        a[j-2] += 2 + a[j] + a[j-1];
        j -= 2;
    }
}
cout << acc << endl;
return 0;
}
```

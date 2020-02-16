---
layout: post
redirect_from:
  - /blog/2016/05/23/hackerrank-may-world-codesprint-xor-quadruples/
date: 2016-05-23T01:50:16+09:00
tags: [ "competitive", "writeup", "hackerrank", "world-codesprint", "meet-in-middle" ]
"target_url": [ "https://www.hackerrank.com/contests/may-world-codesprint/challenges/xor-quadruples" ]
---

# HackerRank May World CodeSprint: Beautiful Quadruples

## problem

整数$A,B,C,D$が与えられる。以下の制約を満たす4つ組$(W,X,Y,Z)$の数を数えよ。

-   $1 \le W \le A$
-   $1 \le X \le B$
-   $1 \le Y \le C$
-   $1 \le Z \le D$
-   $A \le B \le C \le D$
-   $W \le X \le Y \le Z$
-   $W \oplus X \oplus Y \oplus Z \ne 0$
    -   $\oplus$は排他的論理和

## solution

Use meet-in-middle technique. $O(N^2)$.

Let $A \le B \le C \le D$ and $W \le X \le Y \le Z$.
Make $\operatorname{cnt}\_l(s) = \|\\{ (y,z) \mid l \le y \le z, y \oplus z = s \\}\|$ and calculate $\rm{ans} = \Sigma\_{1 \le x \le B} \Sigma\_{1 \le w \le \min \\{ x, A \\}} (\rm{total} - \operatorname{cnt}\_x(w \oplus x))$.
You can construct $\operatorname{cnt}\_{x+1}$ from $\operatorname{cnt}\_x$ with $O(N)$.

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <array>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
typedef long long ll;
using namespace std;
int main() {
    array<int,4> a; repeat (i,4) cin >> a[i];
    sort(a.begin(), a.end());
    vector<ll> cnt(pow(2,ceil(log2(a[3]+1))));
    ll acc = 0;
    repeat_from (y,1,a[2]+1) {
        repeat_from (z,y,a[3]+1) {
            cnt[y^z] += 1;
            acc += 1;
        }
    }
    ll ans = 0;
    repeat_from (x,1,a[1]+1) {
        repeat_from (w,1,min(a[0],x)+1) {
            ans += acc - cnt[w^x];
        }
        int y = x;
        repeat_from (z,x,a[3]+1) {
            cnt[y^z] -= 1;
            acc -= 1;
        }
    }
    cout << ans << endl;
    return 0;
}
```

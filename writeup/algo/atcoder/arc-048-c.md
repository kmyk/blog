---
layout: post
alias: "/blog/2016/05/17/arc-048-c/"
title: "AtCoder Regular Contest 048 C - 足の多い高橋君"
date: 2016-05-17T22:34:14+09:00
tags: [ "competitive", "writeup", "atcoder", "gcd" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc048/tasks/arc048_c" ]
---

分かってしまえば簡単であるが、これを思い付くのは難しそう。

## solution

[editorial[(http://www.slideshare.net/chokudai/arc048)。
回文性から再帰的に分割ができる。gcdをする。$O(N)$。

独立な骨の数$p$を数え、$2^p$を答えればよい。

とりあえず列$L$をsortする。
最小のもの$L_0$を考えると、これとまったく同じ文字列が他の全ての足の末尾に位置しなければならない。
さらに、どんな足の繋げ方を考えても、$L_0$に関連する文字列は他の部分に影響しない。
また$L_0$の骨への文字の書き入れ方は独立である。
よって、独立な骨の数$p$に$L_0$を追加し、すべての足から長さ$L_0$を引き長さ$0$の足を除去することができる。
ただし代わりに、

-   どんな足もそれ単体で回文でなければならない

という制約を追加する。
以下、このような制約の下で話す。

$\operatorname{pal}$は回文であるという述語とする。
上の議論から、全ての足$A,B$に関し、

-   $\operatorname{pal}(A^{-1})$
-   $\operatorname{pal}(B)$
-   $\operatorname{pal}(A^{-1} \oplus B)$

である。
ここから出発して、制約を増やしていく。

-   $\|A\| \le \|B\|$

であるとすると、

-   $B = B' \oplus A$
-   $\operatorname{pal}(B')$

である必要がある。
整理すると、

-   $\operatorname{pal}(A)$
-   $\operatorname{pal}(B')$
-   $\operatorname{pal}(B' \oplus A)$

である。$\|A\| \le \|B'\|$を再度仮定し、同様に再帰的に仮定を増やしていくと、

-   $\operatorname{pal}(A)$
-   $\operatorname{pal}(C)$
-   $\operatorname{pal}(A \oplus C)$
-   $\|C\| = \|B\| \bmod \|A\|$

となって止まる。
$A,B$の役割を逆にして同様にすれば、

-   $\operatorname{pal}(C)$
-   $\operatorname{pal}(D)$
-   $\operatorname{pal}(C \oplus D)$
-   $\|D\| = \|A\| \bmod \|C\|$

となる。

この$\bmod$となる操作を再帰的に行う。
これはEuclidの互除法のstepそのものなので、$A,B$はそれぞれ長さ$\gcd(\|A\|,\|B\|)$の周期を持つこととなる。
特に、その$1$周期自体も回文である。

このような操作を全ての足の間で行なえば、ある単一の回文$c$があって、全ての足は$c$の繰り返しである。
$\|c\|$は全ての足のgcd総和である。
よって、$L_0$を削ってあったことを思い出せば、独立な骨の数$p = L_0 + \lfloor \frac{\Sigma^{\gcd}\_{1 \le i \le N-1}(L_i - L_0)}{2} \rfloor$である。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
int gcd(int a, int b) {
    if (b < a) swap(a,b);
    while (a) {
        int c = a;
        a = b % c;
        b = c;
    }
    return b;
}
ll powi(ll x, ll y, ll p) {
    x = (x % p + p) % p;
    ll z = 1;
    for (ll i = 1; i <= y; i <<= 1) {
        if (y & i) z = z * x % p;
        x = x * x % p;
    }
    return z;
}
const int mod = 1e9+7;
int main() {
    int n; cin >> n;
    vector<int> l(n); repeat (i,n) cin >> l[i];
    sort(l.begin(), l.end());
    int p = l[0];
    if (l.size() >= 2) {
        int q = accumulate(l.begin() + 2, l.end(), l[1] - l[0], [&](int acc, int li) {
            return gcd(acc, li - l[0]);
        });
        p += (q + 1) / 2;
    }
    cout << powi(2, p, mod) << endl;
    return 0;
}
```

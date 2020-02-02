---
layout: post
alias: "/blog/2016/05/26/arc-054-c/"
title: "AtCoder Regular Contest 054 C - 鯛焼き"
date: 2016-05-26T00:12:57+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "matrix", "determinant", "permanent" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc054/tasks/arc054_c" ]
---

検索力と数学力が必要。

## solution

行列式に帰着。$O(N^3)$。

完全二部マッチングの数え上げである。
ぐぐると、$n \times n$の$0,1$の行列のpermanent[^2]の値に等しいこと、その値の多項式時間での計算方法は知られていないことが分かる[^1]。

よって、求めるのが偶奇だけでよいという仮定を利用するのだと分かる。
ここで、permanentの式とdeterminantの式が類似していることに注目する。

-   $\operatorname{perm}(A) = \Sigma\_{\sigma \in S_n} \Pi\_{i = 1}^n a\_{i,\sigma(i)}$
-   $\operatorname{det}(A) = \Sigma\_{\sigma \in S_n} \operatorname{sgn}(\sigma) \Pi\_{i = 1}^n a\_{i,\sigma(i)}$

両者の違いは$\operatorname{sgn}(\sigma)$の有無だけである。
$\operatorname{sgn}(\sigma) \in { 1, -1 }$であるので、$\bmod 2$の下でこれは無視でき、両者は一致する。
よって、単に行列式を求めるだけでよい。

行列式は$O(N^3)$で求められる。基本変形を繰り返して三角行列化し、対角成分の積を取ればよい。

## implementation

行列式を求めるのを書きたくなかったのでnumpyを試したが、floatの上ででしか計算ができずかつ精度がどうにもならなかった。
固有値やらLU分解やらを調べてどうにかしようとしたがだめだったので、普通に実装した。思っていたよりかなり軽かった。

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
using namespace std;

int boolean_determinant(vector<vector<int> > a) {
    int n = a.size();
    repeat (z,n) { // make A upper trianglar
        if (a[z][z] == 0) { // swap rows to avoid zero-division
            int x;
            for (x = z+1; x < n; ++ x) {
                if (a[x][z] != 0) {
                    a[z].swap(a[x]);
                    break;
                }
            }
            if (x == n) return 0; // A is singular
        }
        repeat_from (y,z+1,n) {
            repeat_from (x,z+1,n) {
                a[y][x] ^= a[y][z] * a[z][x]; // elim
            }
        }
    }
    int acc = 1;
    repeat (z,n) acc *= a[z][z]; // product of the diagonal elems
    return acc;
}

int main() {
    int n; cin >> n;
    vector<vector<int> > m(n, vector<int>(n));
    repeat (y,n) repeat (x,n) {
        char c; cin >> c;
        m[y][x] = (c == '1');
    }
    cout << (boolean_determinant(m) == 0 ? "Even" : "Odd") << endl;
    return 0;
}
```

---

[^1]: <http://www.kurims.kyoto-u.ac.jp/~kyodo/kokyuroku/contents/pdf/1799-01.pdf>
[^2]: <https://en.wikipedia.org/wiki/Permanent>

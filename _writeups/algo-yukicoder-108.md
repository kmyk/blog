---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/108/
  - /blog/2016/10/06/yuki-108/
date: "2016-10-06T05:51:12+09:00"
tags: [ "competitive", "writeup", "yukicoder", "expected-value", "dp", "probability" ]
"target_url": [ "http://yukicoder.me/problems/no/108" ]
---

# Yukicoder No.108 トリプルカードコンプ

この手の期待値DPは何度もやってる。

## solution

DP。$N$種類のカードがあるが何枚足りてないかだけが重要で、$1,2,3$枚足りてないカードの数から期待値への関数$\mathrm{dp} : N+1 \times N+1 \times N+1 \to \mathbb{Q}$をすればよい。

>   一般に確率$p$で起こるものが起こるまで試行し続けるとき、その回数の期待値$E = \Sigma\_{k=1}^{\infty} kp(1-p)^{k-1} = \frac{1}{p}$である。

ので[^1]これを使って、$$ \mathrm{dp}(i,j,k) = \frac{i+j+k}{n} + \frac{i}{i+j+k}\mathrm{dp}(i-1,j+1,k) + \frac{j}{i+j+k}\mathrm{dp}(i,j-1,k+1) + \frac{k}{i+j+k}\mathrm{dp}(i,j,k-1) $$。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <array>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
template <typename T, typename X> auto vectors(T a, X x) { return vector<T>(x, a); }
template <typename T, typename X, typename Y, typename... Zs> auto vectors(T a, X x, Y y, Zs... zs) { auto cont = vectors(a, y, zs...); return vector<decltype(cont)>(x, cont); }
int main() {
    int n; scanf("%d", &n);
    vector<int> a(n); repeat (i,n) scanf("%d", &a[i]);
    array<int,3> cnt = {}; repeat (i,n) if (a[i] < 3) cnt[a[i]] += 1;
    array<int,3> l; repeat (i,3) l[i] = (i ? l[i-1] : 0) + cnt[i];
    vector<vector<vector<double> > > dp = vectors(double(), l[0]+1, l[1]+1, l[2]+1);
    repeat (i,l[0]+1) {
        repeat (j,l[1]+1-i) {
            repeat (k,l[2]+1-i-j) {
                if (i == 0 and j == 0 and k == 0) continue;
                double p = (i + j + k) /(double) n;
                double qi = i /(double) (i + j + k);
                double qj = j /(double) (i + j + k);
                double qk = k /(double) (i + j + k);
                dp[i][j][k] = 1/p;
                if (i-1 >= 0 and j+1 < l[1]+1) dp[i][j][k] += qi * dp[i-1][j+1][k];
                if (j-1 >= 0 and k+1 < l[2]+1) dp[i][j][k] += qj * dp[i][j-1][k+1];
                if (k-1 >= 0                 ) dp[i][j][k] += qk * dp[i][j][k-1];
            }
        }
    }
    printf("%.12f\n", dp[cnt[0]][cnt[1]][cnt[2]]);
    return 0;
}
```

[^1]:    過去の記事って便利だよね: <https://kimiyuki.net/blog/2016/04/28/dice-and-expected-value/>

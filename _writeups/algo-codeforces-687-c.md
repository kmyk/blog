---
layout: post
redirect_from:
  - /writeup/algo/codeforces/687-c/
  - /blog/2016/06/30/cf-687-c/
date: 2016-06-30T05:21:01+09:00
tags: [ "competitive", "writeup", "codeforces", "dp" ]
"target_url": [ "http://codeforces.com/contest/687/problem/C" ]
---

# Codeforces Round #360 (Div. 1) C. The Values You Can Make

`vector<vector<bool> >`にしててTLEった。こういうのなくせばratingは100以上上がると思うんだけどなくなってくれない。

## problem

整数$k$と$c_0, \dots, c\_{n-1}$が与えられる。
$X \subseteq n = \\{ 0, \dots, n-1 \\}$に対し、$f(X) = \Sigma\_{x \in X} c_x$と定める。
$\phi_k(y) = \exists X Y. f(X) = k \land Y \subseteq X \land y \in Y$を満たすような$y$を全て出力せよ。

## solution

DP. $O(nk^2)$.

Let $\mathrm{dp} : k+1 \to \mathcal{P}(k+1)$ be $\mathrm{dp}(x) = \\{ y \mid \phi_x(y) \\}$, the set of sums of subsets of the subsets whose sum is $x$.
Update this function for each coin $c_i$ with $O(k^2)$ simply, then the complexity is $O(nk^2)$ in total. 

## implementation

Don't use `vector<set<int> >` or `vector<vector<int> >`. Use `vector<vector<bool> >` or the similar one.

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
#define whole(f,x,...) ([&](decltype((x)) y) { return (f)(begin(y), end(y), ## __VA_ARGS__); })(x)
using namespace std;
int main() {
    // input
    int n, k; cin >> n >> k;
    vector<int> cs(n); repeat (i,n) cin >> cs[i];
    // calc
    vector<vector<bool> > f(k+1, vector<bool>(k+1));
    f[0][0] = true;
    for (int c : cs) {
        repeat_reverse (i,k+1) {
            int j = i-c;
            if (j < 0) break;
            repeat (x,k+1) if (f[j][x]) {
                f[i][x    ] = true;
                f[i][x + c] = true;
            }
        }
    }
    // output
    cout << whole(count, f[k], true) << endl;
    int j = 0;
    repeat (x,k+1) if (f[k][x]) {
        if (j ++) cout << ' ';
        cout << x;
    }
    cout << endl;
    return 0;
}
```

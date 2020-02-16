---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-014-d/
  - /blog/2015/12/25/arc-014-d/
date: 2015-12-25T19:11:53+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "cumulative-sum" ]
---

# AtCoder Regular Contest 014 D - grepマスター

順位表を見て分かる通り、D問題にしてはかなり簡単。

## [D - grepマスター](https://beta.atcoder.jp/contests/arc014/tasks/arc014_4) {#d}

### 解説

あるヒットした行に関して、その行の前$x$行と後ろ$y$行が表示できるかできないかに影響するのは、その前後のヒットした行(あるいはファイルの始まりと終わり)のみである。
したがって、ヒットした行を中心に考えるのではなく、ヒットした行と行の間の行たちに関して考えればよい。

数列$L$が与えられるが、この階差数列$D$と初項$L_1$及び最終項$L_N$のみがあれば十分である。
ファイルの始まりから最初のヒットした行、$1$から$l-1$の間の行で、表示されるのは$\min \\{ x, L_1 - 1 \\}$である。
同様に最後にヒットした行とファイルの終わりは、$\min \\{ y, {\rm all} - L_N \\}$。
ヒットした行と行の間の$D_i$行は、$\min \\{ D_i, x + y \\}$である。
これらに、ヒットした行そのものの$N$を加えたものが結果である。

$NM \le 10^5$であるので、愚直に計算すると間に合わない。
$\Sigma\_{i = 1}^N \min \\{ D_i, x + y \\}$を高速に計算したい。
そこで、$A\_{x+y} = \\{ D_i \mid D_i \lt x + y \\}$を用いて、$\Sigma \min \\{ D_i, x + y \\} = \Sigma A\_{x+y} + (N - |A\_{x+y}|)(x + y)$と変形する。
このような$A_z$に関して、$\Sigma A_z$と$|A_z|$は、事前に累積和を(おそらく`map`上で)作っておくことにより高速に計算できる。

### 実装

``` c++
#include <iostream>
#include <vector>
#include <map>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
typedef long long ll;
struct acc_t { ll acc; int rest; };
int main() {
    // input
    int a, n, m; cin >> a >> n >> m;
    vector<int> ls(n); repeat (i,n) cin >> ls[i];
    // prepare
    map<int,int> diffs;
    repeat (i,n-1) diffs[ls[i+1] - ls[i] - 1] += 1;
    map<int,acc_t> accs;
    accs[-1] = (acc_t){ 0, n-1 };
    for (auto p : diffs) {
        int diff = p.first;
        int count = p.second;
        acc_t acc = accs.rbegin()->second;
        accs[diff] = (acc_t){ acc.acc + diff *(ll) count, acc.rest - count };
    }
    int l = ls.front() - 1;
    int r = a - ls.back();
    // answer
    repeat (i,m) {
        int x, y; cin >> x >> y;
        auto it = accs.upper_bound(x + y);
        acc_t acc = it == accs.end() ? accs.rbegin()->second : (-- it)->second;
        cout << min(l,x) + acc.acc + acc.rest *(ll) (x + y) + n + min(r,y) << endl;
    }
    return 0;
}
```

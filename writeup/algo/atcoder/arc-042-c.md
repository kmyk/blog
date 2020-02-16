---
layout: post
redirect_from:
  - /blog/2015/10/06/arc-042-c/
date: 2015-10-06T14:42:44+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "dp", "order", "sort", "knapsack", "monotonicity" ]
---

# AtCoder Regular Contest 042 C - おやつ

本番解けなかったのを解いた。良い問題だと思う。

<!-- more -->

## [C - おやつ](https://beta.atcoder.jp/contests/arc042/tasks/arc042_c) {#c}

### 問題

ナップサック系の問題。
任意の1つのおやつについてそれを除いた合計金額がP円に収まるようにおやつを選んで、幸福度を最大化する。

### 解法

単純に値段$\times$最小金額に関してdpすると、$P\times a$の表を$N$回更新するので$O(NPa)$となり間に合わない。

事前におやつを金額で降順に整列しておけば、現在見ているおやつの金額が既に選ばれているおやつの最小金額より小さいことが保証され、$O(NP)$で計算できる。

### 実装

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
using namespace std;
struct item_t { int a, b; };
bool operator < (item_t const & x, item_t const & y) { return make_pair(x.a, x.b) < make_pair(y.a, y.b); }
int main() {
    int n, p; cin >> n >> p;
    vector<item_t> xs(n); repeat (i,n) cin >> xs[i].a >> xs[i].b;
    sort(xs.rbegin(), xs.rend());
    const int pl = p + 100 + 1;
    vector<int> cur(pl);
    vector<int> prv(pl);
    repeat (i,n) {
        cur.swap(prv);
        repeat (j, pl) {
            cur[j] = prv[j];
            int k = j - xs[i].a;
            if (0 <= k and k <= p) cur[j] = max(cur[j], prv[k] + xs[i].b);
        }
    }
    cout << *max_element(cur.begin(), cur.end()) << endl;
    return 0;
}
```

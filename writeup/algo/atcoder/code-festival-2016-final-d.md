---
layout: post
redirect_from:
  - /writeup/algo/atcoder/code-festival-2016-final-d/
  - /blog/2016/11/28/code-festival-2016-final-d/
date: "2016-11-28T02:15:12+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf16-final-open/tasks/codefestival_2016_final_d" ]
---

# CODE FESTIVAL 2016 Final: D - Pair Cards

## solution

$X_i \bmod M$で分類して$a + b \equiv 0 \pmod{M}$な類の対$(a,b)$ごとに見る。$O(N)$。

各$k$ ($0 \le k \lt M$)について、余りが$k$になる整数の数$a_k = \|\\{ i \mid k \equiv X_i \pmod{M} \\}\|$、同じ整数のペアで余りが$k$なものの数$b_k = \sum\_{y \equiv k \pmod{M}} \lfloor \frac{\|\\{ i \mid X_i = y \\}\|}{2} \rfloor$を求める。
そのような対の組$(a_k, b_k), (a\_{M-k}, b\_{M-k})$を取ると、$c = \lfloor \frac{\min \\{ a_k, a\_{M-k} \\}}{2} \rfloor$として$n = c + \max \\{ 0, b_k - c \\} + \max \\{ b\_{M-k} - c \\}$個の$2$枚組が取れる。同じ整数同士の$2$枚組に使えない整数から使うべき、同じ整数同士の$2$枚組にできても足して$M$な組を作って損しないことから、正当性はある程度信じることができる。$k = M-k$な場合は例外なことに注意しつつ足し合わせる。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <map>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
int main() {
    // input
    int n, m; cin >> n >> m;
    map<int,int> xs;
    repeat (i,n) {
        int x; cin >> x;
        xs[x] += 1;
    }
    // compute
    vector<int> cnt(m), pr(m);
    for (auto it : xs) {
        int x, k; tie(x, k) = it;
        cnt[x % m] += k;
        pr [x % m] += k / 2 * 2;
    }
    int ans = 0;
    repeat (i,m) {
        int j = (m - i) % m;
        if (i == j) {
            ans += cnt[i] / 2;
        } else if (i < j) {
            int k = min(cnt[i], cnt[j]);
            ans += k;
            ans += min(cnt[i] - k, pr[i]) / 2;
            ans += min(cnt[j] - k, pr[j]) / 2;
        }
    }
    // output
    cout << ans << endl;
    return 0;
}
```

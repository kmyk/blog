---
layout: post
redirect_from:
  - /writeup/algo/aoj/1261/
  - /blog/2015/10/17/aoj-1261/
date: 2015-10-17T20:51:16+09:00
tags: [ "aoj", "icpc", "competitive", "writeup", "rpn" ]
"target_url": [ "!-- more --" ]
---

# AOJ 1261 Mobile Computing

## [Mobile Computing](http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=1261) (ICPC Asia 2005 E) {#e}

### 問題

長さ$1.0$の棒を用いて与えられた重りを繋げ飾りを作る(問題文中の図参照)。
部屋の幅rを越えないように繋げたときの飾りの幅の最大値を求めよ。

### 解法

重りの繋ぎ方を逆ポーランド記法で表すことを考える。
例えば、

```
  |
+-+---+
1     |
  +---+-+
  2     3
```

という繋げ方は、中置記法で`1 * (2 * 3)`と表せ、逆ポーランド記法では`123**`である。
こうすれば`next_permutation`を用いて簡単に全て列挙でき、stackに積みながら舐めることで幅を計算でき、$O(s!{}\_{2s-1}C\_{s-1}s)$で解ける。

### 解答

``` c++
#include <iostream>
#include <cstdio>
#include <vector>
#include <stack>
#include <algorithm>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
using namespace std;
struct mobile_t {
    int w; // weight
    double l; // left
    double r; // right
};
const double eps = 0.0001;
double evaluate(vector<int> const & p) {
    stack<mobile_t> stk;
    for (int w : p) {
        if (w == 0) {
            if (stk.size() < 2) return -1;
            mobile_t x = stk.top(); stk.pop();
            mobile_t y = stk.top(); stk.pop();
            mobile_t z;
            z.w = x.w + y.w;
            double dx = y.w /(double) (x.w + y.w);
            double dy = x.w /(double) (x.w + y.w);
            z.l = max(x.l + dx, y.l - dy);
            z.r = max(x.r - dx, y.r + dy);
            stk.push(z);
        } else {
            stk.push((mobile_t){ w, 0.0, 0.0 });
        }
    }
    if (stk.size() != 1) return -1;
    return stk.top().l + stk.top().r;
}
int main() {
    int datasets; cin >> datasets;
    repeat (dataset, datasets) {
        double r; cin >> r;
        int s; cin >> s;
        vector<int> w(s); repeat (i,s) cin >> w[i];
        double result = -1;
        vector<int> p;
        repeat (i,s)   p.push_back(w[i]);
        repeat (i,s-1) p.push_back(0);
        sort(p.begin(), p.end());
        do {
            double it = evaluate(p);
            if (r + eps < it) continue;
            result = max(result, it);
        } while (next_permutation(p.begin(), p.end()));
        if (result == -1) {
            printf("-1\n");
        } else {
            printf("%.16lf\n", result);
        }
    }
    return 0;
}
```

---

# AOJ 1261 Mobile Computing

icpcのための練習会で解いた。私の不要な一言で、重りを繋げるときにひっくり返す返さないの情報を入れるべきだと勘違いしてしまった。

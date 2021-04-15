---
layout: post
redirect_from:
  - /writeup/algo/codeforces/codeforces-333/
  - /blog/2015/09/10/codeforces-333/
date: 2015-09-10T22:59:34+09:00
tags: [ "codeforces", "competitive", "writeup" ]
"target_url": [ "http://codeforces.com/contest/333" ]
---

# Codeforces Round #194 (Div. 1)

茶会。Cは飛ばしたがDが解けたので嬉しい。

<!-- more -->

## [A. Secrets](http://codeforces.com/contest/333/problem/A) {#a}

問題文が難しかった。それを理解したのは開始30分後であった。中身は簡単。

### 問題

$3^n (n \ge 0)$円硬貨のみを持つ国での話。
硬貨の組で、合計額は$n$円より大きいが、$n$円ちょうどを払うことはできないような組がある。
そのような硬貨の組で、合計金額の最小の額の組は、最大何枚の硬貨であるか。

例えば10円に対しては、条件を満たし金額が最小で枚数が最大の組は3円硬貨4枚であり、答は4。

### 解答

``` python
   #!/usr/bin/env python3
   n = int(input())
   while n % 3 == 0:
   n = n // 3
   print(n // 3 + 1)
```

## [B. Chips](http://codeforces.com/contest/333/problem/B) {#b}

解けた。実質的に無視できる制約の多い問題だった。

-   上下左右に動けるが、$n-1$回しか移動できないので、辺から辺へ一直線に移動すると考えてよい。
-   行と列を選び向きを定める問題、と再解釈できる。
-   駒が衝突してはいけないが、全ての駒が盤の中心を軸に時計周り/反時計周りに移動すれば、ちょうど中央の駒を除いて、衝突することはない。

``` c++
#include <iostream>
#include <set>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
using namespace std;
int main() {
    int n, m; cin >> n >> m;
    set<int> xs, ys;
    repeat (i,m) {
        int x, y; cin >> x >> y;
        xs.insert(x);
        ys.insert(y);
    }
    xs.insert(1); xs.insert(n);
    ys.insert(1); ys.insert(n);
    int x = n - xs.size();
    int y = n - ys.size();
    int p = 0; if (n % 2 == 1 and not xs.count(n/2+1) and not ys.count(n/2+1)) p = -1;
    cout << x + y + p << endl;
    return 0;
}
```

## [D. Characteristics of Rectangles](http://codeforces.com/contest/333/problem/D) {#d}

解けた。$n \le 1000$だったので書いてみた愚直な$O(n^3)$を高速化したら通ってしまった。
[editorial](http://codeforces.com/blog/entry/8418)曰く、想定解法は$O(n^2 \log n)$。

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#include <cassert>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
using namespace std;
int main() {
    int h, w; scanf("%d%d", &h, &w);
    vector<vector<int> > a(h, vector<int>(w));
    repeat (y,h) repeat (x,w) scanf("%d", &a[y][x]);
    vector<int> snd(h);
    repeat (y,h) {
        vector<int> b = a[y];
        sort(b.rbegin(), b.rend());
        snd[y] = b[1];
    }
    int result = 0;
    repeat (y1,h) {
        if (snd[y1] <= result) continue;
        repeat_from (y2,y1+1,h) {
            if (snd[y2] <= result) continue;
            int z[2] = {};
            repeat (x,w) {
                int v = min(a[y1][x], a[y2][x]);
                if (z[0] < v) {
                    z[0] = v; // z[0] = max(z[0], v);
                    if (z[0] > z[1]) swap(z[0], z[1]); // sort(z, z+2);
                }
            }
            if (result < z[0]) result = z[0]; // result = max(result, z[0]);
        }
    }
    printf("%d\n", result);
    return 0;
}
```

今回に限らず一般のテストケースでも`column -t`使うといいのではと気付いた

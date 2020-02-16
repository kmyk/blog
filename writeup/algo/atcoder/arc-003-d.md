---
layout: post
alias: "/blog/2015/09/27/arc-003-d/"
date: 2015-09-27T17:58:34+09:00
tags: [ "atcoder", "arc", "competitive", "writeup" ]
---

# AtCoder Regular Contest 003 D - シャッフル席替え

敗北。答えにかすりもしなかった。
乱択解を思いつけたことない気がする。

<!-- more -->

## [D - シャッフル席替え](https://beta.atcoder.jp/contests/arc003/tasks/arc003_4) {#d}

制限時間が10秒かつ$N \le 11$の円順列は$3.6 {\rm e} 6$個なので、これに$K$と${}_NC_2$が掛かっても上手くやれば通るのだろうと思い、ずっとDPのようなものを考えていた。
前処理して区別する必要のない人々を同一視する等、色々試してみたが間に合わず。
答え見たらもっと単純だった。
許容誤差が変に大きいなとは感じたのだが、$({}_NC_2)^K \sim 6.4 {\rm e} 34$と大きいからかなあ、と勝手に納得し忘れてしまっていた。

### 解法

>   誤差は絶対誤差あるいは相対誤差の少なくとも片方が 2e−3 以下であれば許容する。

と許容誤差が大きいので乱択解。モンテカルロ法。

### 解答

``` c++
   #include <random>
   #include <ctime>
   #include <iostream>
   #include <cstdio>
   #include <vector>
   #include <set>
   #include <algorithm>
   #include <cassert>
   #define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
   #define repeat(i,n) repeat_from(i,0,n)
   using namespace std;
   bool ok(vector<int> const & a, set<pair<int,int> > const & forbidden) {
   int n = a.size();
   repeat (i,n) {
       pair<int,int> p = { a[i], a[(i+1)%n] };
       if (forbidden.count(p)) return false;
   }
   return true;
   }
   int main() {
   clock_t start = clock();
   int n, m, k; cin >> n >> m >> k;
   set<pair<int,int> > forbidden;
   repeat (i,m) {
       int a, b; cin >> a >> b;
       forbidden.emplace(a, b);
       forbidden.emplace(b, a);
   }
   default_random_engine gen;
   uniform_int_distribution<int> dist(0,n-1);
   long long x = 0, y = 0;
   while ((clock() - start) /(double) CLOCKS_PER_SEC < 9.5) {
       vector<int> a(n);
       repeat (i,n) a[i] = i;
       repeat (i,k) {
           int p = dist(gen);
           int q = p; while (q == p) q = dist(gen);
           swap(a[p], a[q]);
       }
       if (ok(a, forbidden)) ++ x;
       ++ y;
   }
   printf("%.12lf\n", x /(double) y);
   return 0;
   }
```

atcoderの`clock()`は正確

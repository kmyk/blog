---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc-011-d/
  - /blog/2017/03/12/agc-011-d/
date: "2017-03-12T22:48:20+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "experiment", "simd" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc011/tasks/agc011_d" ]
---

# AtCoder Grand Contest 011: D - Half Reflector

$N = 2 \times 10^5$かつ$K = 10^9$で$O(NK)$が通るの楽しい。

## solution

実験して規則性。定数倍がとても軽い$O(NK)$、あるいはまじめに書いて$O(N)$。

観察により以下が分かる。これを元に適当に書けばよい。

-   末尾の`BA`は無視できる
-   先頭が`A`なら、先頭が`B`になるだけ
-   先頭が`B`なら、`A` `B`が反転しひとつ左にずれる (rotateなので末尾には`A`)
    -   例: `BAAABBAAABABABA` $\to$ `BBBAABBBABABABA`
-   $N$が偶数なら、最終的に変化しなくなる
-   $N$が奇数なら、最終的に先頭が`A`と`B`の間で振動する

## implementation

AVX命令 `vmovups`が吐かれた。`sizeof(bool)`は$1$になってるようなので$32$倍速か。

``` c++
#include <cstdio>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;
constexpr size_t max_n = 200000;
bool a[max_n+1];
int main() {
    int n, k; scanf("%d%d", &n, &k);
    repeat (i,n) { char c; scanf(" %c", &c); a[i] = (c == 'A'); }
    int m = n;
    a[m] = false;
    while (k --) {
        if (a[0]) {
            a[0] = false;
        } else {
            repeat (i,m) a[i] = not a[i+1];
        }
        while (2 <= m and not a[m-2] and a[m-1]) m -= 2;
        if (m == 0) break;
        if (m == 1) k %= 2;
    }
    repeat (i,n) printf("%c", a[i] ? 'A' : 'B');
    printf("\n");
    return 0;
}
```

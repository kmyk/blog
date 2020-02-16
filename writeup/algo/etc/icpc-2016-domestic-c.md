---
layout: post
redirect_from:
  - /blog/2016/06/27/icpc-2016-domestic-c/
date: 2016-06-27T13:01:53+09:00
tags: [ "competitive", "writeup", "icpc", "sieve-of-eratosthenes", "greedy" ]
---

# ACM-ICPC 2016 国内予選 C: 竹の花

-   <http://icpcsec.storage.googleapis.com/icpc2016-domestic/problems/all_ja.html#section_C>
-   <http://icpc.iisf.or.jp/past-icpc/domestic2016/judgedata/C/>

## solution

エラトステネスの篩っぽい感じにやる貪欲。
答が取り得る値の最大値を$A$として、$O(A \log \log A)$。
なお$A$の値は問題文に書いてあって、$A = 7368791$である。

-   $a \ge m$でかつまだ使われていないような最小の$a$について、それは使わなければならない。
-   $a$を使ったとき、$ka$ for all $k \ge 1$についてこれを使われたことにできる。

## implementation

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
const int size = 7368791 + 1;
int main() {
    while (true) {
        int m, n; cin >> m >> n;
        if (m == 0 and n == 0) break;
        vector<bool> used(size);
        int j = m;
        repeat (i,n) {
            while (used[j]) ++ j;
            for (int k = j; k < used.size(); k += j) {
                used[k] = true;
            }
        }
        while (used[j]) ++ j;
        cout << j << endl;
    }
    return 0;
}
```

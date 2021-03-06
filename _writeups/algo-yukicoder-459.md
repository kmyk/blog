---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/459/
  - /blog/2016/12/10/yuki-459/
date: "2016-12-10T09:11:31+09:00"
tags: [ "competitive", "writeup", "yukicoder", "greedy" ]
"target_url": [ "http://yukicoder.me/problems/no/459" ]
---

# Yukicoder No.459 C-VS

CodeVSは相手の出力が与えられないのでその算出が面倒だなあと思ったが、こういうところから作問に繋げればよいっぽい？

## solution

貪欲。左から埋めていく。入力$O(HW + N)$で計算$O(W + N)$。

まず、入力は$2$次元の`.`/`#`で与えられるが、これは`#`の高さという$1$次元に直してよい。
また、パックを降らせる順序は無視してよい。

各パック最低$1$ブロックの制約がある。これが面倒。
そこで先に貪欲に各パックに$1$ブロックずつ割り当てておけば、この制約が消え、各列が独立になる。
あとは再度貪欲すればよい。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <array>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;
int main() {
    // input
    int h, w, n; scanf("%d%d%d", &h, &w, &n);
    vector<int> a(w);
    repeat (y,h) repeat (x,w) {
        char c; scanf(" %c", &c);
        if (c =='#') a[x] += 1;
    }
    vector<int> c(n);
    vector<vector<int> > c_inv(w-2);
    repeat (i,n) {
        scanf("%d", &c[i]);
        c_inv[c[i]].push_back(i);
    }
    // solve
    vector<array<int,3> > b(n);
    repeat (x,w-2) {
        for (int i : c_inv[x]) {
            repeat (dx,3) {
                if (a[x + dx]) {
                    a[x + dx] -= 1;
                    b[i][dx] += 1;
                    break;
                }
            }
        }
    }
    repeat (x,w) {
        repeat (dx,3) if (0 <= x-dx and x-dx < w-2) {
            for (int i : c_inv[x-dx]) {
                while (a[x] and b[i][dx] < 3) {
                    a[x] -= 1;
                    b[i][dx] += 1;
                }
            }
        }
    }
    // output
    for (auto & it : b) {
        repeat (y,3) {
            repeat (x,3) {
                printf("%c", 3-y-1 < it[x] ? '#' : '.');
            }
            printf("\n");
        }
    }
    return 0;
}
```

---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/334/
  - /blog/2016/02/11/yuki-334/
date: 2016-02-11T22:11:32+09:00
tags: [ "competitive", "writeup", "yukicoder", "dp", "bit-dp" ]
---

# Yukicoder No.334 門松ゲーム

門松列の定義に、

>   全ての値が異なり

っての見落しててちょっと困った。

grundy数は使いようがない問題なはず。

## [No.334 門松ゲーム](http://yukicoder.me/problems/930)

### 解法

全ての状態に関して先手必勝か判定する。bit dpあるいはメモ化再帰。$O(2^N N^3)$。

数列の状態はそれぞれの数が消されているか消されていないかなので$2^N$通り。$N \le 12$なので$2^N \le 4096$。
それぞれの状態に関して、その状態から初めた時に先手必勝であるか後手必勝であるかを計算すればよい。
高々${}\_NC_3$個の遷移先を全て見て、後手必勝であるような状態に遷移できるような状態は先手必勝であり、そのような遷移先がない状態は後手必勝である。

### 実装

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
using namespace std;
bool is_kadomatsu(int a, int b, int c) {
    if (a == b or b == c or c == a) return false;
    if (a < b and b < c) return false;
    if (a > b and b > c) return false;
    return true;
}
int main() {
    int n; cin >> n;
    vector<int> k(n); repeat (i,n) cin >> k[i];
    vector<bool> dp(1<<n); // grundy number
    repeat (s, 1<<n) {
        repeat (a,n) if (s & (1<<a)) {
            repeat_from (b,a+1,n) if (s & (1<<b)) {
                repeat_from (c,b+1,n) if (s & (1<<c)) {
                    if (not is_kadomatsu(k[a], k[b], k[c])) continue;
                    if (not dp[s & ~ ((1<<a) | (1<<b) | (1<<c))]) {
                        dp[s] = true;
                        goto done;
                    }
                }
            }
        }
        done:;
    }
    repeat (a,n) {
        repeat_from (b,a+1,n) {
            repeat_from (c,b+1,n) {
                if (not is_kadomatsu(k[a], k[b], k[c])) continue;
                if (not dp[((1<<n)-1) & ~ ((1<<a) | (1<<b) | (1<<c))]) {
                    cout << a << ' ' << b << ' ' << c << endl;
                    return 0;
                }
            }
        }
    }
    cout << -1 << endl;
    return 0;
}
```

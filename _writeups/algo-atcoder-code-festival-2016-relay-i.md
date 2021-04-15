---
layout: post
redirect_from:
  - /writeup/algo/atcoder/code-festival-2016-relay-i/
  - /blog/2016/11/30/code-festival-2016-relay-i/
date: "2016-11-30T01:33:32+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf16-relay-open/tasks/relay_i" ]
---

# CODE FESTIVAL 2016 Relay: I - 目があったら負け / 3y3s Challenge

本番で担当した。やはり焦ってしまって、普段ならしない実装のミスを連発した。そういえば一昨年も似たことしてたなあ。

ところで何故問題タイトルはleetになってるのだろう。

## solution

単純に思い付くのは、各時刻$t$で全員が同時に$t$個先の人を見るという戦略。
これは$N$が奇数なら成功するが、$N$が偶数のときはちょうど$t = \frac{N}{2}$において失敗する。
そこで偶数のとき、$\frac{N}{2}$番から$N-1$番目の人々について、$t_0 = \frac{N}{2}$と$t_1 = \frac{N}{2}+1$とで見る先を交換する。
これで問題なく動くことが証明できる。
交換前の$t = \frac{N}{2}$において互いに見つめ合っていたのでその組の片方を変化させれば見つめ合いは発生しないことを主に言えばよい。
ただし$N = 2$の場合は自明に不可能。

## implementation

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }
int main() {
    int n; cin >> n;
    if (n == 2) {
        cout << -1 << endl;
    } else {
        vector<vector<int> > f = vectors(n, n-1, int());
        repeat (i,n) repeat (j,n-1) f[i][j] = (i+j+1)%n;
        // swap
        if (n%2 == 0) {
            int k = n/2;
            repeat_from (j,k,n) {
                swap(f[j][k-1], f[j][k]);
            }
        }
        // output
        repeat (i,n) {
            repeat (j,n-1) {
                if (j) cout << ' ';
                cout << f[i][j]+1;
            }
            cout << endl;
        }
    }
    return 0;
}
```

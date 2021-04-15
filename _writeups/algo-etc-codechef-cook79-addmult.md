---
layout: post
redirect_from:
  - /writeup/algo/etc/codechef-cook79-addmult/
  - /blog/2018/04/05/codechef-cook79-addmult/
date: "2018-04-05T06:48:51+09:00"
tags: [ "competitive", "writeup", "codechef", "game" ]
"target_url": [ "https://www.codechef.com/COOK79/problems/ADDMULT" ]
---

# CodeChef Cook79: D. To add or to multiply game

## problem

Chef と Chefu が次のようなゲームをしている:
最初に数列が与えられる。隣接する2項を削除し、その積/和どちらかを選んでこれで置き換えることを繰り返す。
最終的に偶数が残れば Chef の勝ち、奇数が残れば Chefu の勝ち。

数列と先手となる人が与えられるので勝者を答えよ。

## solution

偶奇だけ考えればよい。
最後の手番が Chef のものなら自明に Chef の勝ち。
そうでないとしても Chef が有利で、`11`を`0`に置換することはできても`00`は`0`にしかならないため。
最後の Chefu の手番でひとつでも`1`が残っていれば Chefu の勝ちなので、それまでにChef が`1`を消し切れるか判定すればよい。
これはいい感じに`1`の数を数えて回ってくる手番の数と比較すればできる。
$O(N)$。

$N = 1$がコーナーケースになりうる。

## note

-   なんで名前が `Chef` と `Chefu` なんだ無意味に区別しにくくするのやめろという気持ち (これは罠でAtCoderでも `snuke` と `snake` とかはある)

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;

bool solve(int n, bool first, vector<bool> a) {
    if (n == 1) return a[0];
    bool last = (n % 2 == 0 ? first : not first);
    if (not last) {
        return false;  // can always make 0
    } else {
        int k = 0;
        for (int i = 0; i < n; ) {
            if (a[i] == 0) {
                ++ i;
            } else {
                ++ k;
                ++ i;
                if (i < n and a[i] == 1) ++ i;
            }
        }
        return k > (n - first) / 2;  // the number of plays by Chef
    }
}

int main() {
    int t; cin >> t;
    while (t --) {
        int n; cin >> n;
        string first; cin >> first;
        vector<bool> a(n);
        REP (i, n) {
            int a_i; cin >> a_i;
            a[i] = a_i & 1;  // consider only parities
        }
        bool result = solve(n, first == "Chefu", a);  // Chefu wants to make 1
        cout << (result ? "Chefu" : "Chef") << endl;
    }
    return 0;
}
```

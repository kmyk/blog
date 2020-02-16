---
layout: post
redirect_from:
  - /blog/2016/12/25/agc-008-d/
date: "2016-12-25T23:01:25+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "greedy", "construction" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc008/tasks/agc008_d" ]
---

# AtCoder Grand Contest 008: D - K-th K

レート持ってかれた。

## 反省

Cまでで時間使いすぎに焦りが加わって間に合わず。

## solution

貪欲に埋める。$O(N)$。

各$i$について、$x_i$の左に$i-1$個、右に$n-i$個置けばよい。
最も左の項$a_1$を何にすべきか考えると、$x_i$の値が最も小さい$i$にするのが妥当。
そうでなく$j \ne i$にしないと失敗するとすると、$a_1$から$x_j$までまったく余裕がないことになるが、これを$x_i$の取り方と合わせるといずれにせよ失敗する。
$a_2$以降も同様に、(まだ$x_i$の左に$i-1$個置いてないような$i$の中で)$x_i$の値が最も小さい$i$にするのが妥当。
このようにして置けば左に$i-1$個の制約が満たされる。これを満たした後逆向きに同様にすれば、右に$n-i$個の制約も満たされ$a$が構成される。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <numeric>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;
int main() {
    // input
    int n; cin >> n;
    vector<int> x(n); repeat (i,n) { cin >> x[i]; -- x[i]; }
    // solve
    vector<int> a(n*n, -1);
    repeat (i,n) a[x[i]] = i;
    vector<int> ix(n);
    whole (iota, ix, 0);
    whole (sort, ix, [&](int i, int j) { return x[i] < x[j]; });
    int j = 0;
    for (int i : ix) {
        for (int k = 0; k < i; ) {
            assert (j < n*n);
            if (a[j] == -1) {
                a[j] = i;
                ++ k;
            } else if (a[j] == i) {
                a.clear();
                goto done;
            }
            ++ j;
        }
    }
    whole(reverse, ix);
    j = n*n-1;
    for (int i : ix) {
        for (int k = 0; k < n-i-1; ) {
            assert (j >= 0);
            if (a[j] == -1) {
                a[j] = i;
                ++ k;
            } else if (a[j] == i) {
                a.clear();
                goto done;
            }
            -- j;
        }
    }
done: ;
    // output
    if (a.empty()) {
        cout << "No" << endl;
    } else {
        cout << "Yes" << endl;
        repeat (i,n*n) {
            if (i) cout << ' ';
            cout << a[i] + 1;
        }
        cout << endl;
    }
    return 0;
}
```

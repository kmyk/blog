---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc-010-e/
  - /blog/2017/02/17/agc-010-e/
date: "2017-02-17T22:52:54+09:00"
tags: [ "competitive", "writeup", "atcoder", "game" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc010/tasks/agc010_e" ]
---

# AtCoder Grand Contest 010: E - Rearranging

適当にやればできるという感じがあったので流れで書いたらなんとなく通った。ただしそのような書き方の常として、不注意なバグを埋めて苦しんだ。

## solution

連結成分ごとに順序を立てて、仕上げに挿入ソート。$O(N^2)$。

互いに素でない数同士を辺で結んでグラフを作る。これは非連結であり、制約の範囲は各連結成分内で閉じている。
連結成分内で最も端に持ってきたい数を決めて、それからのDFSの訪問順に並べれば上手くいく。
DFSでなくBFSとかだとだめで、反例としては`2 6 30 10`みたいな合流するもの。

後攻の行うのはただの整列なのでそのようにやる。挿入ソートがよい。ただし貪欲に見るだけだと不足することに注意。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;
int gcd(int a, int b) { while (a) { b %= a; swap(a, b); } return b; }
bool is_swappable(int a, int b) { return gcd(a, b) == 1; }
int main() {
    // input
    int n; cin >> n;
    vector<int> a(n); repeat (i,n) cin >> a[i];
    // rearrange
    whole(sort, a);
    vector<int> b;
    vector<bool> used(n);
    function<void (int)> go = [&](int i) {
        used[i] = true;
        b.push_back(a[i]);
        repeat (j,n) if (not used[j] and not is_swappable(a[i], a[j])) {
            go(j);
        }
    };
    repeat (i,n) if (not used[i]) {
        go(i);
    }
    // insertion sort
    repeat (i,n) {
        int j = i;
        for (int k = i-1; k >= 0 and is_swappable(b[k], b[i]); -- k) {
            if (b[k] < b[i]) j = k;
        }
        rotate(b.begin() + j, b.begin() + i, b.begin() + i + 1);
    }
    // output
    for (auto it : b) cout << it << ' '; cout << endl;
    return 0;
}
```

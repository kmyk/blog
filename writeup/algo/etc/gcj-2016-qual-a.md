---
layout: post
alias: "/blog/2016/04/10/gcj-2016-qual-a/"
date: 2016-04-10T11:04:16+09:00
tags: [ "competitive", "writeup", "google-code-jam", "gcj" ]
"target_url": [ "https://code.google.com/codejam/contest/6254486/dashboard#s=p0" ]
---

# Google Code Jam 2016 Qualification Round A. Counting Sheep

I've noticed that, people who visit this blog are not only Japanese.
So I'll try to write solutions in English, for problems written in English.

## problem

集合値関数$f : \mathbb{N} \to \mathcal{P}(\mathbb{N})$を、$f(n) = \\{ 整数$n$の$10$進数表記に数字として含まれる数 \\}$とする。
例えば$f(1692) = \\{ 1, 2, 6, 9 \\}$である。

整数$N$が与えられる。
$f(N) \cup f(2N) \cup \dots f(kN) = \\{ 0, 1, 2, \dots 9 \\}$となるような$kN$が存在するか判定し、存在するならば最小の$kN$を答えよ。

## solution

$N = 0$ diverges. Otherwise, you should only simply count from $1 \cdot N$ to certain $k \cdot N$ (exists), until all digits appeared.

To make sure of this, you can implement it and run it for many cases.

## implementation

``` c++
#include <iostream>
#include <array>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
void solve() {
    ll n; cin >> n;
    if (n == 0) {
        cout << "INSOMNIA" << endl;
    } else {
        array<bool,10> used = {};
        int i = 1;
        while (true) {
            for (ll t = i * n; t; t /= 10) used[t % 10] = true;
            if (not count(used.begin(), used.end(), false)) break;
            ++ i;
        }
        cout << i * n << endl;
    }
}
int main() {
    int t; cin >> t;
    repeat (i,t) {
        cout << "Case #" << i+1 << ": ";
        solve();
    }
    return 0;
}
```

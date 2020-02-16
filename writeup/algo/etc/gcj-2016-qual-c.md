---
layout: post
redirect_from:
  - /blog/2016/04/10/gcj-2016-qual-c/
date: 2016-04-10T11:04:27+09:00
tags: [ "competitive", "writeup", "google-code-jam", "gcj" ]
"target_url": [ "https://code.google.com/codejam/contest/6254486/dashboard#s=p2" ]
---

# Google Code Jam 2016 Qualification Round C. Coin Jam

## problem

`0`と`1`のみからなる文字列がある。
これを$2 \le i le 10$などの$i$進数として解釈しても素数でないとき、良い文字列であるとする。
長さが$N$の良い文字列を$J$個出力せよ。ただし、各文字列に対し、良い文字列であることの証拠として約数$p_i$($2 \le i \le 10$)を全て示せ。

## solution

only doing.
Generate random strings and sellect the good strings.

To select good ones, you can simply try to divede it with many small integers.
When it is not divided with the trials, even if it is a composite number actually, you can ignore it.

## implementation

boost is nice.

``` c++
#include <iostream>
#include <vector>
#include <set>
#include <random>
#include <boost/multiprecision/cpp_int.hpp>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
using namespace std;
namespace mp = boost::multiprecision;
void solve() {
    random_device device;
    default_random_engine gen(device());
    uniform_int_distribution<int> dist(0,1); // bool
    int n, j; cin >> n >> j;
    set<string> used;
    while (used.size() < j) {
        string s; s += '1'; repeat (i,n-2) s += dist(gen) + '0'; s += '1';
        if (used.count(s)) continue;
        vector<int> witnesses;
        repeat_from (base,2,10+1) {
            mp::cpp_int p = 0;
            repeat (i,n) {
                p *= base;
                if (s[i] == '1') p += 1;
            }
            repeat_from (i,2,10000) {
                if (p % i == 0) {
                    witnesses.push_back(i);
                    goto next;
                }
            }
            break;
next:;
        }
        if (witnesses.size() == 9) {
            cout << s;
            for (int it : witnesses) cout << ' ' << it;
            cout << endl;
            used.insert(s);
        }
    }
}
int main() {
    int t; cin >> t;
    repeat (i,t) {
        cout << "Case #" << i+1 << ":" << endl;
        solve();
    }
    return 0;
}
```

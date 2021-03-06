---
layout: post
redirect_from:
  - /writeup/algo/aoj/1195/
  - /blog/2017/06/27/aoj-1195/
date: "2017-06-27T23:40:53+09:00"
tags: [ "competitive", "writeup", "aoj", "icpc" ]
"target_url": [ "http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=1195" ]
---

# AOJ 1195: 暗号化システム / Encryption System

軽い定数倍高速化が必要ぽい。後輩に書かせたらTLEしていた。

## solution

暗号化によって変化した位置の候補を総当たり。$2^n$通りあるそれぞれについて、戻して再度暗号化してみて一致するか見る。文字列の長さ$n = \|s\|$に対し$O(n2^n)$。

## implementation

``` c++
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f, x, ...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;

constexpr int n_max = 20;
int main() {
    while (true) {
        array<char, n_max+1> s;
        scanf("%s", s.data());
        if (s[0] == '#') break;
        int n = strlen(s.data());
        int cnt = 0;
        vector<string> acc;
        repeat (modified, 1 << n) {
            array<bool, 26> used = {};
            used[0] = true;
            bool invalid = false;
            repeat (i, n) {
                char c = s[i];
                if (modified & (1 << i)) {
                    if (c == 'z') {
                        invalid = true;
                        break;
                    } else {
                        c += 1;
                    }
                }
                if (not used[c-'a']) {
                    used[c-'a'] = true;
                    c -= 1;
                }
                if (s[i] != c) {
                    invalid = true;
                    break;
                }
            }
            if (invalid) continue;
            string t;
            repeat (i, n) {
                char c = s[i] + bool(modified & (1 << i));
                t += c;
            }
            cnt += 1;
            acc.push_back(t);
            whole(sort, acc);
            if (acc.size() == 11) acc.erase(acc.begin() + 5);
        }
        whole(sort, acc);
        printf("%d\n", cnt);
        for (string t : acc) {
            printf("%s\n", t.c_str());
        }
    }
    return 0;
}
```

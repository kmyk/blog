---
layout: post
redirect_from:
  - /writeup/algo/aoj/2435/
  - /blog/2017/07/01/aoj-2435/
date: "2017-07-01T23:56:35+09:00"
tags: [ "competitive", "writeup", "aoj", "jag-summer" ]
"target_url": [ "http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=2435" ]
---

# AOJ 2435: Zero Division Checker

よくわかる数式処理。

## solution

ほとんど指示された通りに実装する。
整数の範囲は$[0, 256)$なので、`bitset<256>`とかにしてありえる可能性全部を持つようにする。$k = 256$として定数$k^2$が乗る$O(M)$。

## implementation

``` c++
#include <algorithm>
#include <bitset>
#include <iostream>
#include <stack>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i, m, n) for (int i = (m); (i) < int(n); ++(i))
#define whole(f, x, ...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;

int main() {
    // input
    int m; cin >> m;
    vector<string> name(m);
    vector<int> l(m), r(m); // [l, r]
    repeat (i, m) {
        cin >> name[i] >> l[i] >> r[i];
    }
    int n; cin >> n;
    vector<string> es(n);
    repeat (i, n) {
        cin >> es[i];
    }
    // solve
    bool result = true;
    stack<bitset<256> > stk;
    for (string e : es) {
        if (isdigit(e[0])) {
            bitset<256> num = {};
            num[stoi(e)] = true;
            stk.push(num);
        } else if (isalpha(e[0])) {
            int i = whole(find, name, e) - name.begin();
            bitset<256> var = {};
            repeat_from (j, l[i], r[i] + 1) {
                var[j] = true;
            }
            stk.push(var);
        } else {
            bitset<256> b = stk.top(); stk.pop();
            bitset<256> a = stk.top(); stk.pop();
            if (e == "/" and b[0]) {
                result = false;
                break;
            }
            bitset<256> c = {};
            repeat (i, 256) if (a[i]) {
                repeat (j, 256) if (b[j]) {
                    if (e == "+") {
                        c[(i + j) % 256] = true;
                    } else if (e == "-") {
                        c[(i - j + 256) % 256] = true;
                    } else if (e == "*") {
                        c[i * j % 256] = true;
                    } else if (e == "/") {
                        c[i / j] = true;
                    }
                }
            }
            stk.push(c);
        }
    }
    // output
    cout << (result ? "correct" : "error") << endl;
    return 0;
}
```

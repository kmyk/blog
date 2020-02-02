---
layout: post
alias: "/blog/2015/10/25/codefestival-2015-qualb/"
title: "CODE FESTIVAL 2015 予選B"
date: 2015-10-25T22:10:49+09:00
tags: [ "competitive", "writeup", "codefestival" ]
---

予選Aはぎりぎりだったが、予選Bは好成績。

<!-- more -->

## [A - ダブル文字列/Double String](https://beta.atcoder.jp/contests/code-festival-2015-qualb/tasks/codefestival_2015_qualB_a) {#a}

### 実装

oneliner

``` brainfuck
,.----------[++++++++++.,.----------]
```

``` sh
sed -e 's/.*/&&/'
```

後から知ったが、単に`aabbccddeeffgghhiijjkkllmmnnooppqqrrssttuuvvwwxxyyzz`を提出しても通る。

## [B - 採点/Grading](https://beta.atcoder.jp/contests/code-festival-2015-qualb/tasks/codefestival_2015_qualB_b) {#b}

### 解法

素直にやる

### 実装

``` python
#!/usr/bin/env python3
n, m = map(int,input().split())
a = list(map(int,input().split()))
b = dict(zip(range(m+1), [0] * (m+1)))
for i in a:
    b[i] += 1
p = max(b.items(), key=lambda p: p[1])
if n / 2 < p[1]:
    print(p[0])
else:
    print('?')
```

## [C - 旅館/Hotel](https://beta.atcoder.jp/contests/code-festival-2015-qualb/tasks/codefestival_2015_qualB_c) {#c}

本番は`multiset`とか使った回りくどいコードを提出したが、よく考えたらかなり単純だった。

### 解法

それぞれの大きい方から順に見ていけばよい

### 実装

``` python
#!/usr/bin/env python3
n, m = map(int,input().split())
a = map(int,input().split())
b = map(int,input().split())
if n < m:
    print('NO')
else:
    if all(map(lambda p: p[0] >= p[1],
            zip(sorted(a, reverse=True), sorted(b, reverse=True)))):
        print('YES')
    else:
        print('NO')
```

## [D - マスと駒と色塗り/Squares, Pieces and Coloring](https://beta.atcoder.jp/contests/code-festival-2015-qualb/tasks/codefestival_2015_qualB_d) {#d}

実装手間なのにあまりバグらさなかった、成長を感じる。

### 問題

白いマスが横一列に並んでいる。無限に長いものと考えてよい。
ある位置$s_i$から右に向かって、まだ白いマスを$c_i$個黒く塗り、最後に塗ったマスの位置を答える、という操作を$n$回行なう。

### 解法

シミュレートすれは済む。
愚直に`bool`の配列で管理すると時間も空間も足りないので、黒と白の境界だけ保持する。

つまり`{ 3: '[', 6: ')', 8: '[', 9: ')' }`で`..xxx..x.............`という状態を表すなどとして、丁寧に更新していけばよい。

### 実装

だいたい$O(n \log n)$

``` c++
#include <iostream>
#include <vector>
#include <map>
#include <cassert>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
typedef long long ll;
using namespace std;
int main() {
    int n; cin >> n;
    vector<ll> s(n), c(n);
    repeat (i,n) cin >> s[i] >> c[i];
    map<ll,char> a;
    repeat (i,n) {
        while (c[i] > 0) {
            auto it = a.lower_bound(s[i]);
            if (it == a.end()) {
                a[s[i]] = '[';
                a[s[i] + c[i]] = ')';
                s[i] += c[i];
                c[i] = 0;
            } else {
                assert (s[i] <= it->first);
                if (it->second == '[') {
                    if (it->first == s[i]) {
                        s[i] += 1;
                    } else if (s[i] + c[i] < it->first) {
                        a[s[i]] = '[';
                        a[s[i] + c[i]] = ')';
                        s[i] += c[i];
                        c[i] = 0;
                    } else {
                        int t = s[i];
                        s[i] = it->first;
                        c[i] -= it->first - t;
                        assert (0 <= c[i]);
                        a.erase(it);
                        a[t] = '[';
                    }
                } else {
                    assert (it->second == ')');
                    s[i] = it->first;
                    auto that = it;
                    ++ that;
                    assert (that == a.end() or that->second == '[');
                    if (that == a.end() or s[i] + c[i] < that->first) {
                        s[i] += c[i];
                        c[i] = 0;
                        a.erase(it);
                        a[s[i]] = ')';
                    } else {
                        c[i] -= that->first - it->first;
                        s[i] = that->first;
                        a.erase(it);
                        a.erase(s[i]);
                        assert (0 <= c[i]);
                    }
                }
            }
        }
        cout << s[i] - 1 << endl;
#if 0
repeat (i,180) {
    cerr << (a.count(i) ? a[i] : '.');
}
cerr << endl;
#endif
    }
    return 0;
}
```

---
layout: post
redirect_from:
  - /blog/2016/04/16/gcj-2016-round1a-a/
date: 2016-04-16T15:23:39+09:00
tags: [ "competitive", "writeup", "gcj", "google-code-jam", "greedy" ]
"target_url": [ "https://code.google.com/codejam/contest/4304486/dashboard#s=p0" ]
---

# Google Code Jam 2016 Round 1A A. The Last Word

Reading the English of the problem statement was more tiring than solving this.

## problem

文字列$S$がある。
文字列$T$を空文字列から始めて、$S$の文字を先頭から順に取り出し、$T$の先頭か末尾に加える。
このようにして$S$の文字を$T$に全て移すことで生成されるような$T$の中で、辞書順最大のものを答えよ。

## solution

greedy. $O(N)$.

compare the character of $S$ to add and the 1st character of $T$.

## implementation

``` c++
#include <iostream>
#include <deque>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
void solve() {
    string s; cin >> s;
    deque<char> t;
    for (char c : s) {
        if (t.empty() or c < t.front()) {
            t.push_back(c);
        } else {
            t.push_front(c);
        }
    }
    for (char c : t) cout << c;
    cout << endl;
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

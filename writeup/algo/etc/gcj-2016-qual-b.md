---
layout: post
redirect_from:
  - /writeup/algo/etc/gcj-2016-qual-b/
  - /blog/2016/04/10/gcj-2016-qual-b/
date: 2016-04-10T11:04:22+09:00
tags: [ "competitive", "writeup", "google-code-jam", "gcj", "greedy" ]
"target_url": [ "https://code.google.com/codejam/contest/6254486/dashboard#s=p1" ]
---

# Google Code Jam 2016 Qualification Round B. Revenge of the Pancakes

I like this.

## problem

`+`と`-`からなる文字列がある。
以下の操作を繰り返して`+`のみの文字列を作るとき、必要な操作回数の最小値を答えよ。

-   文字列の左から$i$文字の部分に関して、順序を反転させ、`+`と`-`を入れ替える。
    -   例えば`+--+++`を`+--`と`+++`に分ければ、`+--`を反転し`--+`、`--+`を入れ替えて`++-`、結果として`++-+++`を得る。

## solution

Greedy. $O(TN^2)$.
Repeat flipping the leftmost `+`s or `-`s.

Or $O(TN)$.
Count the compressed length.

### proof

You can see the contiguous `+`s or `-`s as single `+` or `-`, and ignore the trailing `+`s.
So the string must like `-+-+-+-` or `+-+-+-`.
And the goal is equivalent to empty string.

For each one flip, you can make the string shorter, by at most length $1$: for example, flip `-+-` of `-+-+-`, then `+-++-` equals `+-+-`.
Also, obviously, always there are ways to flip with decreasesing the length.

Therefore, the answer equals to the (compressed) length of the input string.

## implementation

### O(TN)

is `std::unique` enough?

``` c++
#include <iostream>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
using namespace std;
void solve() {
    string s; cin >> s;
    int n = s.length();
    string t;
    repeat_reverse (i,n) {
        if (t.empty() and s[i] == '+') continue;
        if (t.empty() or t.back() != s[i]) t.push_back(s[i]);
    }
    cout << t.length() << endl;
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

### O(TN^2)

My first code.
I did implement an unnecessary things.

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
void solve() {
    string s; cin >> s;
    auto flip = [&](int r) {
        string t = s;
        repeat (i,r) t[i] = s[r-i-1] == '+' ? '-' : '+';
        s = t;
    };
    int ans = 0;
    while (s.find('-') != string::npos) {
        if (s[0] == '+') {
            flip(s.find('-'));
        } else {
            flip(s.rfind('-') + 1);
        }
        ++ ans;
    }
    cout << ans << endl;
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

---
layout: post
redirect_from:
  - /writeup/algo/topcoder/srm-688-easy/
  - /blog/2016/04/16/srm-688-easy/
date: 2016-04-16T04:42:59+09:00
tags: [ "competitive", "writeup", "topcoder", "srm" ]
---

# TopCoder SRM 688 Easy: ParenthesesDiv1Easy

I wrote a greedy one and got WA.

## problem

`(`と`)`のみからなる文字列が与えられる。これから始めて以下の変換を$10$回以内行いbalanceさせられるか。
可能なら具体的な変換位置まで示せ。

-   $l \le r$を変数に取る。文字列$s$の内、$s_l, s\_{l+1} \dots, s_r$の部分の順序を反転し、また`(`と`)`を入れ換える。
    -   つまり、$f(\it{\`( '}) = \it{\`) '}, f(\it{\`) '}) = \it{\`( '}$として、$s \mapsto ( s_0, s_1, \dots, s\_{l-1}, f(s_r), f(s\_{r-1}), \dots, f(s_l), s\_{r+1}, s\_{r+2}, \dots, s\_{n-1} )$

## solution

The flips at most twice is enough. $O(N)$.

The flip has a property: preserves the balanced-ness of substrings in its range.
For example, if you flip a string `))))((()())()))))`, made of unbalanced `))))`, balanced `((()())())` and unbalanced `)))`, then you get `((((()(()()))((((`, made of unbalanced `(((`, balanced `(()(()()))` and unbalanced `((((`. The balanced-ness of `((()())())` are preserved.

So you can ignore the balanced substrings and think the unbalanced parens.
You can think `)())(()()))()(` as `)**)******)**(` or simply `)))(`.
Such simplified strings can be classified as one of the three: all closing `)))...)))`, all opening `(((...(((` or both `)))...)(((...(`.
Now, all you have to do is to flip them, and this is enough at most twice.

## implementation

I thank [roiti](https://twitter.com/roiti46) for his python code.

``` c++
#include <bits/stdc++.h>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
class ParenthesesDiv1Easy { public: vector<int> correct(string s); };

vector<int> ParenthesesDiv1Easy::correct(string s) {
    int n = s.size();
    if (n % 2 == 1) return { -1 };
    vector<int> t;
    repeat (i,n) {
        if (not t.empty() and s[t.back()] == '(' and s[i] == ')') {
            t.pop_back();
        } else {
            t.push_back(i);
        }
    }
    if (t.empty()) return {}; // s is balanced
    char fst = s[t.front()];
    char lst = s[t.back()];
    int sz = t.size();
    if (fst == ')' and lst == '(') { // t = ")))...)))(((...((("
        int l = count_if(t.begin(), t.end(), [&](int i) { return s[i] == '('; });
        int r = sz - l;
        int d = abs(r - l);
        if (l < r) {
            return { t[0], t[r-1-d/2], t[sz-l], t[sz-1] };
        } else if (l > r) {
            return { t[0], t[r-1], t[sz-l+d/2], t[sz-1] };
        } else {
            return { t[0], t[sz/2-1], t[sz/2], t[sz-1] };
        }
    } else if (fst == ')' and lst == ')') { // t = ")))...)))"
        return { t[0], t[sz/2-1] };
    } else if (fst == '(' and lst == '(') { // t = "(((...((("
        return { t[sz/2], t[sz-1] };
    }
}
```

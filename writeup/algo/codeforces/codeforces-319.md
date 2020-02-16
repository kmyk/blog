---
layout: post
redirect_from:
  - /blog/2015/09/01/codeforces-319/
date: 2015-09-01T01:14:51+09:00
tags: [ "codeforces", "competitive", "writeup" ]
"target_url": [ "http://codeforces.com/contest/319" ]
---

# Codeforces Round #189 (Div. 1)

解いたらまとめを書いていこうと思った。

<!-- more -->

茶会[^1]にて。1完。

## [A. Malek Dance Club](http://codeforces.com/contest/319/problem/A) {#a}

実験した。

本番はc++で書いた。与えられる2進数100桁整数の取り扱いが面倒だった。実際バグらせてかなり手間取った。LLつよい。

``` python
#!/usr/bin/env python3
p = 1000000007
s = input()
print(int(s,2) * pow(2, len(s) - 1) % p)
```

## [B. Psychos in a Line](http://codeforces.com/contest/319/problem/B) {#b}

本番解けず。editorialより。

要約: `i`番目の人は、彼より左にいて彼より強くて彼に最も近い人を`j`番目の人とすると、開区間`(j,i)`に含まれる人が全員死んだ次の時刻に死ぬ。


``` c++
#include <iostream>
#include <vector>
#include <stack>
#include <algorithm>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
using namespace std;
int main() {
    int n; cin >> n;
    vector<int> a(n); repeat (i,n) cin >> a[i];
    vector<int> t(n); // i番目の人の死ぬ時間
    stack<int> s; // indexに関して昇順、強さに関して降順
    repeat (i,n) {
        // この時点で、sの中の誰かがiを殺す
        t[i] = 1;
        while (not s.empty() and a[s.top()] < a[i]) {
            t[i] = max(t[i], t[s.top()] + 1); // while脱出後にmax_elementするとO(n^2)
            s.pop();
        }
        // この時点で、開区間(s.top(),i)内の人は全てiより弱い
        if (s.empty()) {
            t[i] = 0; // 自分より左に自分より強い人がいない
        }
        s.push(i);
    }
    cout << *max_element(t.begin(), t.end()) << endl;
    return 0;
}
```

先輩はrange minimum query使ってた。editorialにはrandom-access doubly linked list上でsimulationしても解けるよってあった。

---

# Codeforces Round #189 (Div. 1)

[^1]: 部内の練習会

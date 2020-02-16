---
layout: post
alias: "/blog/2015/12/10/srm-675-easy/"
date: 2015-12-10T23:20:32+09:00
tags: [ "competitive", "writeup", "topcoder", "srm", "graph" ]
---

# TopCoder SRM 675 Div1 Easy: TreeAndPathLength3

$2\cdot{}\_aC_2$であるところを${}_aC_2$にしてWA。
紙の上で考えてたときは分かっていたのに、何時の間にか頭から消えてしまっていた。
0完で青に落ちた。

<!-- more -->

## [Easy: TreeAndPathLength3](https://community.topcoder.com/stat?c=problem_statement&pm=14089&rd=16625)

### 解法

![](a.png)

<!--
    ```
        graph G {
            graph[bgcolor="#00000000"];
            node[shape="circle", style="filled", fillcolor="#ffffffff"];
            0 -- 1 -- 2 -- 3;
            0 -- 4 -- 5;
            0 -- 6 -- 7;
            0 -- 8 -- 9;
            0 -- 10 -- 11;
            3 -- 12;
            3 -- 13;
            3 -- 14;
            3 -- 15;
        }
    ```
    -->

`0 -- 1 -- 2 -- 3`の部分を中心に、`i -- i+1 -- 0`を$a$本、`3 -- j`を$b$本生やすと、頂点数$2a+4+b$、長さ3の道数$a(a+1) + (b+1)$のグラフになる。
これで、制約を満たすものは全て作れる。

### 実装

``` c++
#include <bits/stdc++.h>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;

class TreeAndPathLength3 {
public:
    vector<int> construct(int s) {
        repeat (a,500) {
            int b = s - (a*(a+1) + 1);
            if (0 <= b and 2*a + 4 + b <= 500) {
                return construct(a,b);
            }
        }
        assert (false);
    }
    vector<int> construct(int a, int b) {
        vector<int> g;
        std::function<void (int,int)> e = [&](int v, int w) {
            g.push_back(v);
            g.push_back(w);
        };
        e(0,1);
        e(1,2);
        e(2,3);
        repeat (i,a) {
            int j = 4+2*i;
            e(j,0);
            e(j,j+1);
        }
        repeat (i,b) {
            int j = 4+2*a+i;
            e(j,3);
        }
        return g;
    }
};
```

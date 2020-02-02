---
layout: post
title: "TopCoder 2018 TCO Algorithm: Easy. CubesOnATable"
date: 2018-08-26T02:55:08+09:00
tags: [ "competitive", "writeup", "topcoder", "srm" ]
---

## 解法

$4$を法として$0$になるよう調整してから高く積む。
$O(\mathrm{surface})$。
$\mathrm{surface} = 10$のふたつに分離するケースはコーナーっぽいので注意。

## 実装

``` c++
#include <bits/stdc++.h>
using namespace std;
class CubesOnATable { public: vector<int> placeCubes(int surface); };

vector<int> CubesOnATable::placeCubes(int surface) {
    vector<int> answer;
    map<pair<int, int>, int> height;
    auto push = [&](int x, int y) {
        auto p = make_pair(x, y);
        int z = height[p];
        answer.push_back(x);
        answer.push_back(y);
        answer.push_back(z);
        ++ height[p];
    };
    switch (surface % 4) {
        case 0:
            if (surface < 8) return vector<int>();
            push(0, 0);
            push(0, 1);
            surface -= 8;
            break;
        case 1:
            if (surface < 5) return vector<int>();
            push(0, 0);
            surface -= 5;
            break;
        case 2:
            if (surface < 10) return vector<int>();
            push(0, 0);
            push(0, 2);
            surface -= 10;
            break;
        case 3:
            if (surface < 11) return vector<int>();
            push(0, 0);
            push(0, 1);
            push(0, 2);
            surface -= 11;
            break;
    }
    for (; surface; surface -= 4) {
        push(0, 0);
    }
    return answer;
}
```

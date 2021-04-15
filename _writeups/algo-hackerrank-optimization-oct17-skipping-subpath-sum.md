---
layout: post
redirect_from:
  - /writeup/algo/hackerrank/optimization-oct17-skipping-subpath-sum/
  - /blog/2017/11/10/hackerrank-optimization-oct17-skipping-subpath-sum/
date: "2017-11-10T22:52:04+09:00"
tags: [ "competitive", "writeup", "hackerrank", "kadane-algorithm", "lowest-common-ancestor" ]
"target_url": [ "https://www.hackerrank.com/contests/optimization-oct17/challenges/skipping-subpath-sum" ]
---

# HackerRank Performance Optimization: D. Skipping Subpath Sum

## problem

頂点に重みの付いた木が与えられる。
次のクエリにたくさん答えよ:

-   頂点$u, v$が与えられる。$u, v$間の唯一のpathについて、偶数番目の頂点の重みの総和と奇数番目の頂点の重みの総和のうち大きい方を答えよ。

## solution

根に向かって$1$歩ずつLCAまで登っていき、その過程を貯め込んでいい感じにKadane's algorithm。$O(QN)$。

## 知見

-   数列から総和が最大となるような連続部分列を探すアルゴリズムとして、[Kadane's algorithm](https://en.wikipedia.org/wiki/Maximum_subarray_problem)
    -   順に伸ばしていって総和が負になったらリセットする感じ
    -   名前を知らないだけでみんなやってるやつ

## implementation

``` c++
...

#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(x) begin(x), end(x)
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }

vector<int> skippingSubpathSum(int n, vector<int> const & c, vector<vector<int> > const & graph, vector<pair<int, int> > const & queries) {
    // prepare
    constexpr int root = 0;
    vector<int16_t> parent(n, -1);
    vector<int16_t> depth(n, -1); {
        function<void (int)> go = [&](int i) {
            for (int j : graph[i]) if (parent[j] == -1) {
                parent[j] = i;
                depth[j] = depth[i] + 1;
                go(j);
            }
        };
        parent[root] = root;
        depth[root] = 0;
        go(root);
    }
    // solve
    vector<int> answers;
    for (auto query : queries) {
        // prepare Kadane's algorithm
        int result[2] = {};
        int acc[2] = {};
        int path_size = 0;
        auto kadane = [&](int c_i) {
            int i = (path_size ++) & 1;
            acc[i] += c_i;
            setmax(acc[i], 0);
            setmax(result[i], acc[i]);
        };
        // run
        int u, v; tie(u, v) = query;
        if (depth[u] < depth[v]) {
            swap(u, v);
        }
        assert (depth[u] >= depth[v]);
        for (int depth_u = depth[u]; depth_u > depth[v]; ) {
            kadane(c[u]);
            u = parent[u];
            -- depth_u;
        }
        assert (depth[u] == depth[v]);
        vector<int> stk;
        while (u != v) {
            kadane(c[u]);
            stk.push_back(c[v]);
            u = parent[u];
            v = parent[v];
        }
        kadane(c[u]);
        while (not stk.empty()) {
            kadane(stk.back());
            stk.pop_back();
        }
        // answer
        int answer = max(result[0], result[1]);
        answers.push_back(answer);
    }
    return answers;
}

...
```

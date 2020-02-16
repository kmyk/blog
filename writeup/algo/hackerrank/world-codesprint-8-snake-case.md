---
layout: post
alias: "/blog/2016/12/20/world-codesprint-8-snake-case/"
date: "2016-12-20T02:33:01+09:00"
tags: [ "competitive", "writeup", "hackerrank", "world-codesprint", "golf" ]
"target_url": [ "https://www.hackerrank.com/contests/world-codesprint-8/challenges/snake-case" ]
---

# HackerRank World CodeSprint 8: Snake Case

## implementation

Simple one.

``` python
#!/usr/bin/env python3
print(input().count('_') + 1)
```

perl $19$byte.

``` perl
print s/_//g+1for<>
```

$17$byte bash, but this got WA. It seems there are some test cases which have no newline.

``` sh
tr -cd _\\n|wc -c
```


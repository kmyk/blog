---
layout: post
alias: "/blog/2016/04/09/abc-036-b/"
date: 2016-04-09T22:16:42+09:00
tags: [ "competitive", "writeup", "atcoder", "abc", "brainfuck" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc036/tasks/abc036_b" ]
---

# AtCoder Beginner Contest 036 B - 回転

入れ換えるだけなので楽。
`rev|tac`で簡単に通ったりはしない。

## implementation

### brainfuck

wrapping used.

``` brainfuck
#!/usr/bin/env bf
>
+[,----------] skip a line
+[->,+] read rest
<[<]>[---------->]<< make newline zero
-[+
    [[<]>++++++++++.[-]<+<] print a col
    >+++++++++.[-]>>[[>]>] newline
    <<[<]>
-]
```

### ruby 62byte

``` ruby
n=gets.to_i;s=$/*n,*$<;n.*(n+=1).times{|z|$><<s[n-z%n-1][z/n]}
```

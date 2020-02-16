---
layout: post
redirect_from:
  - /blog/2016/06/04/arc-055-a/
date: 2016-06-04T00:27:11+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "golf", "brainfuck", "sed" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc055/tasks/arc055_a" ]
---

# AtCoder Regular Contest 055 A - 数え上げ

## solution

$1\underbrace{0}\_{n-1}7$。
$1 \le n \le 100$なので$1$byteに収まるし答えは$8$にはならない。

## implementation


### brainfuck $92$byte

$1$桁ずつ読みながら潰していった。
末尾の改行は不要なので出力していない。

[angelさんの提出](https://beta.atcoder.jp/contests/arc055/submissions/752627)が$90$byteと、僅差で負けている。
`+[->,+]`でまとめて読んで後から潰している。

``` brainfuck
#!/usr/bin/env bf
>,>++++++++++[<->>+<-]
0 c *0 10
<[
    n *c 0 10
    ++<[>++++++++++<-]>
    0 *n 0 10
    >,>
    0 n c *10
    [<-<----<+++++>>>>+<-]
    50 n c *0 10
<]
50 n *0 0 10
<<-.
->-[<.>-]
<+++++++.
```

### sed $93$byte

愚直に`\1\1\1\1\1\1\1\1\1\1`と$10$回の繰り返しで潰している。

[%20さんの提出](https://beta.atcoder.jp/contests/arc055/submissions/752525)はもっと短い。`y/123456789/012345678/`でずらして`s/-0/9-/`で繰り下げるそれが使われている。

``` sed
s/./ &9876543210/g
:
s/\(\w*\) \(.\)\w*\2/\1\1\1\1\1\1\1\1\1\1/
t
s/./0/g
s/./1/
s/$/7/
```

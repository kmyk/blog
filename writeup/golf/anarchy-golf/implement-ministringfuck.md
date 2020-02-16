---
layout: post
redirect_from:
  - /blog/2017/01/31/anagol-implement-ministringfuck/
date: "2017-01-31T22:27:35+09:00"
tags: [ "golf", "writeup", "anagol", "anarchy-golf", "brainfuck", "sed" ]
"target_url": [ "http://golf.shinh.org/p.rb?Implement+MiniStringFuck" ]
---

# Anarchy Golf: 999. Implement MiniStringFuck

もはや見慣れたよくあるコードという感じがあるけれど、それでも自己書き換えは好きです。

## implementation

### brainfuck

$25$byte, brainfuck + cheat (self-modifying)

``` brainfuck
$ xxd a.bf
00000000: 2d3c 2b5d 3c5b 3c5d 2b5b 2c5b 3e5d 3e00  -<+]<[<]+[,[>]>.
00000010: 003c 3c5b 3c5d 3e2b 5d                   .<<[<]>+]
```

処理系依存の自己書き換え。$0x10$番地に命令をloadし、$0x1a$番地を下位処理系のメモリとする。

ちゃんとやれば後$2,3$byteは縮むかも

### sed

sed $48$byte

``` sed
/\.\./cHello, World!
cABCDEFGHIJKLMNOPQRSTUVWXYZ
```

おそらく厳密に最短

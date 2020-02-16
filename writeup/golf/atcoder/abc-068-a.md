---
layout: post
alias: "/blog/2018/03/01/abc-068-a/"
date: "2018-03-01T09:49:34+09:00"
tags: [ "competitive", "writeup", "atcoder", "abc", "brainfuck", "golf" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc068/tasks/abc068_a" ]
---

# AtCoder Beginner Contest 068: A - ABCxxx

wrappingの魔法楽しい。手で思い付ける気はしないが。

## implementation

$25$byte $256$-wrapping

``` brainfuck
>+[+[<]>>+<+]>.+.+.,.,.,.
```

`>+[+[<]>>+<+]>` は <https://esolangs.org/wiki/Brainfuck_constants> から拝借。
$(0^\ast, 0, 0, 0)$から始めて$(0, 0, 0, 65^\ast)$を作る。
始めは$(0, 2k + 1, k, 0)$の形で増えていく。
$2k + 1 = 256 \equiv 0$になったところで`[<]`が働かずひとつずれ$(0, 0, 2k' + 128, k' + 1)$の形に。
$k' = 64$のときに$2k' + 128 \equiv 0$となって停止し$k' = 65$が残る。

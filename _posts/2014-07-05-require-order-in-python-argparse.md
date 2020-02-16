---
category: blog
layout: post
date: 2014-07-05T22:06:54+09:00
tags: [ "python", "argparse" ]
---

# pythonのargparseでrequire_order

optionでない引数以降は全て非optionにしたい  
つまり `--foo a --bar b c` を `--foo --bar -- a b c` ではなく `--foo -- a --bar b c` と等価にしたい  
perlのGetOptなどだと`require_order`と`permute`という指定子がありますよね

調べたところ、

-   `nargs=argparse.REMAINDER`を使えば良い
-   `nargs=argparse.PARSER`なら引数がない時失敗 (`*`と`+`のような違い)

他にも`argparse.SUPPRESS`を見つけた  
`description`や`help`といったoption引数に入れるとhelpやusageから消える

documentに書いてなかったりするあたりは注意すべきなのかな

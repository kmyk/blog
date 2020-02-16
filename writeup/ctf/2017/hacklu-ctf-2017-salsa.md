---
layout: post
alias: "/blog/2017/10/20/hacklu-ctf-2017-salsa/"
date: "2017-10-20T01:32:43+09:00"
tags: [ "ctf", "writeup", "hacklu-ctf", "crypto", "salsa20" ]
---

# hack.lu CTF 2017: SALSA

## problem

[Salsa20](https://ja.wikipedia.org/wiki/Salsa20)と呼ばれる暗号。
暗号文と暗号化oracleが与えられるので複合せよ。

## solution

暗号化は`data`を送ると`encrypt(key, nonce, counter, JSON({ "cnt": counter, "data": base64(data) }))`が得られるというもの。
複数回oracleを利用するときの変化はcounterだけ。
結果の形が`{"cnt": ...`で固定であるため分かりにくいが、counterがひとつ増えると同じ文字を暗号化した結果はひとつずれるだけ。
つまり`encrypt(counter, text)[: -1] == encrypt(counter + 1, text)[1 :]`のようになっている。
これが分かればやるだけ。
$64$回の再接続をするような実装だと楽。

## implementation

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='flatearth.fluxfingers.net')
parser.add_argument('port', nargs='?', default=1721, type=int)
parser.add_argument('--log-level', default='debug')
args = parser.parse_args()
context.log_level = args.log_level

import json
def getmsgtext(msg_counter, text):
    msg = {"cnt" : msg_counter, "data" : text[: 128]}
    return json.dumps(msg)
msgtext_offset = getmsgtext(0, '__DATA__').index('__DATA__')

import base64
b64flag = [ '?' ] * 128
b64letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
for i, c in enumerate(b64letters):
    log.info('letter = %c', c)

    with remote(args.host, args.port) as p:
        time.sleep(0.2)
        encoded_flag = p.recv()
        assert len(encoded_flag) == 0x8e
        log.info(fiddling.hexdump(encoded_flag[msgtext_offset :]))

        def query(s):
            p.send(s)
            time.sleep(0.1)
            return p.recv()

        s = query(base64.b64decode(c * 128))
        log.info(fiddling.hexdump(s[msgtext_offset :]))
        for j, (a, b) in enumerate(zip(encoded_flag[msgtext_offset + 1 :], s[msgtext_offset :])):
            if a == b:
                b64flag[1 + j] = c

    log.info('base64(flag) = %s', ''.join(b64flag))
```

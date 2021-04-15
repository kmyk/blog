---
layout: post
redirect_from:
  - /writeup/ctf/2016/33c3-ctf-pay2win/
  - /blog/2016/12/30/33c3-ctf-pay2win/
date: "2016-12-30T13:39:33+09:00"
tags: [ "ctf", "writeup", "web", "33c3-ctf" ]
---

# 33C3 CTF: pay2win

SECCON本戦に向けてweb問中心に解いていた。まだwebは初心者なので経験値と能力の効率がよく、pwnを頑張るより効率がよいという判断。

## solution

buttonがふたつある。cheapとflag。

![](/blog/2016/12/30/33c3-ctf-pay2win/1.png)

まず[cheap](http://78.46.224.78:5001/pay?data=5e4ec20070a567e0b89c74ab16aecd48f2921d05b607154d3b5b0554edda4f8828df361f896eb3c3706cda0474915040)から。

![](/blog/2016/12/30/33c3-ctf-pay2win/2.png)

`9999999999`や`1111111111111111111111111111111111111111` (`<input>`に`maxlength="16"`属性が付いてるのでcurl経由でやる)を送ると認証を通る。

![](/blog/2016/12/30/33c3-ctf-pay2win/3.png)

次は[flag](http://78.46.224.78:5001/pay?data=5e4ec20070a567e0b89c74ab16aecd48fcaa02c2edf4687f4f75c9736d3b8e0641e7995bb92506da1ac7f8da5a628e19ae39825a916d8a2f)。

![](/blog/2016/12/30/33c3-ctf-pay2win/4.png)

だめ。

![](/blog/2016/12/30/33c3-ctf-pay2win/5.png)

URLに付いている`?data=...`の値が怪しい。これを整理すると以下のようになる。一致する部分がいくらかある。

```
/pay              (cheap) 5e4ec20070a567e06ce74ade0984b44f 5c8c244fd5679b023b5b0554edda4f88 28df361f896eb3c3706cda0474915040
/pay              (flag)  5e4ec20070a567e06ce74ade0984b44f d3cecf05a77eeacb4f75c9736d3b8e06 41e7995bb92506da1ac7f8da5a628e19ae39825a916d8a2f
/payment/callback (cheap) 5765679f0870f4309b1a3c83588024d7 c146a4104cf9d2c86842c15a91ea9769 28df361f896eb3c3706cda0474915040
/payment/callback (flag)  232c66210158dfb23a2eda5cc945a0a9 650c1ed0fa0a08f6ca019a8c229bc4d9 aef38fd25e8ce9872f7ef761e2bbe791
```

block暗号のECB modeのように、適当に切り貼りしてみる。以下のように貼り合わせてできる
<http://78.46.224.78:5000/payment/callback?data=5765679f0870f4309b1a3c83588024d7c146a4104cf9d2c86842c15a91ea9769aef38fd25e8ce9872f7ef761e2bbe791>
が正解。

```
/payment/callback (cheap) 5765679f0870f4309b1a3c83588024d7 c146a4104cf9d2c86842c15a91ea9769
/payment/callback (flag)                                                                    aef38fd25e8ce9872f7ef761e2bbe791
```

![](/blog/2016/12/30/33c3-ctf-pay2win/6.png)

flag: `33C3_3c81d6357a9099a7c091d6c7d71343075e7f8a46d55c593f0ade8f51ac8ae1a8`

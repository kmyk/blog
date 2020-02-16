---
layout: post
redirect_from:
  - /blog/2016/04/18/plaidctf-2016-misc/
date: 2016-04-18T06:00:00+09:00
tags: [ "ctf", "misc", "writeup", "plaidctf" ]
---

# PlaidCTF 2016 misc

## plane_site

bucket fill.

You must set the threshold of the tool to $0.0$.

## Untitled-1.pdf

open with an editor, and see the hidden white plain text.

## hevc

convert and play it.

As you can find with `strings`, this is a `H.265/HEVC codec` coded video.
So I tried simply below, and it succeeded.

```
$ ffmpeg -i out_743a4e0cbbfae017e5197b303c82aa52.raw out.mp4
```

## the stuff

use wireshark.

Find the string `flag`, you can get the base64-ed `flag.zip` from the SMTP packets.
Then find the string `password`, you can get the string `super_password1` too.

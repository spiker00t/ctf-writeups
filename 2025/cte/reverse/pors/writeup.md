# (Reverse - CWTE 2025) PORS

TL;DR: Obfuscated program whose logic is encoded in sigreturn frames.

PORS is a challenge I authored for Compete With Team Europe 2025, a
training CTF where all the ECSC national teams play against Team
Europe. It has been solved by 3 teams during the CTF.

## Detailed description

For this challenge we are given two files:
- an ELF x86-64 binary `pors`
- a file `program.bin`

Is that yet another VM challenge? Not this time...

When we run the binary, it prompts us for an input:
```
$ ./pors
Enter your input: azerazerazer
[-] Wrong input, sorry...
```

The binary does the following operations:
- open `program.bin`,
- map three areas at `0x13370000`, `0x42420000`, `0xcafe0000` and
  write some data from `program.bin` into the two former,
- execute a mysterious syscall and exit.

```c
undefined8 FUN_00401206(void)

{
  uint local_30;
  uint local_2c;
  void *local_28;
  void *local_20;
  void *local_18;
  FILE *local_10;
  
  local_10 = fopen("program.bin","r");
  if (local_10 == (FILE *)0x0) {
    puts("[-] Failed to load program :/");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  fread(&local_2c,4,1,local_10);
  local_18 = mmap((void *)0x13370000,(long)(int)((local_2c & 0xfffff000) + 0x1000),7,0x22,-1,0);
  if (local_18 != (void *)0x13370000) {
    puts("[-] init failed, sorry :/");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  fread((void *)0x13370000,1,(long)(int)local_2c,local_10);
  fread(&local_30,4,1,local_10);
  local_20 = mmap((void *)0x42420000,(long)(int)((local_30 & 0xfffff000) + 0x1000),3,0x22,-1,0);
  if (local_20 != (void *)0x42420000) {
    puts("[-] init failed, sorry :/");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  fread((void *)0x42420000,1,(long)(int)local_30,local_10);
  local_28 = mmap((void *)0xcafe0000,0x2000,3,0x22,-1,0);
  if (local_28 != (void *)0xcafe0000) {
    puts("[-] init failed, sorry :/");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  syscall();
  return 0;
}
```

But... where is the actual program? The one that prompts us?

The "mysterious syscall" is a `sigreturn`. 
```
004013c4 48 c7 c4        MOV        RSP,0x42420000
         00 00 42 42
004013cb 48 c7 c0        MOV        RAX,0xf
         0f 00 00 00
004013d2 0f 05           SYSCALL
```

Actually, the area at 0x42420000 contains a whole array of sigreturn
frames, that encodes partially the logic of the program. Sigreturn
frames are especially known for the famous SROP technique used in pwn,
that allows reaching an arbitrary RIP value while controlling the
values of all registers.

The area at 0x13370000 contains the actual "code" of the program,
scattered in small blocks, among them:
- a "dispatcher block"
```
00000004 48 89 d0        MOV        RAX,RDX
00000007 48 83 c0 01     ADD        RAX,0x1
0000000b 48 69 c0        IMUL       RAX,RAX,0xf8
         f8 00 00 00
00000012 48 01 c4        ADD        RSP,RAX
00000015 48 c7 c0        MOV        RAX,0xf
         0f 00 00 00
0000001c 0f 05           SYSCALL
```

- small blocks of code similar to:
```
### executed code ###
00000234 c6 44 24        MOV        byte ptr [RSP + 0x14],0x0
         14 00
### call to dispatcher block ###
00000239 48 c7 c4        MOV        RSP,0x42420000
         00 00 42 42
00000240 48 c7 84        MOV        qword ptr [RSP + 0x88],0x24
         24 88 00 
         00 00 24 
0000024c 48 c7 c0        MOV        RAX,0xf
         0f 00 00 00
00000253 0f 05           SYSCALL
```

This pattern reminds of control flow flattening (CFF), where each
"basic block" runs an elementary amount of code, and calls a
"dispatcher" with the number of the next block to execute (that we
call the successor). Then, the dispatcher jump to the successor.

Here, the number of the successor is stored in RDX when the dispatcher
is called. The dispatcher essentially runs the block `N` by doing a
`sigreturn` with `RSP = 0x42420000 + (N + 1) * <size_of_sigreturn_frame>`: 
each block is associated to the sigreturn
frame corresponding to its number. After running its actual code, each
block calls back the dispatcher by setting RSP to `0x42420000`,
writing the number of the successor at `[RSP + 0x88]` (which
corresponds to RDX in the sigreturn frame) and doing a `sigreturn`
syscall. This is the purpose of the very first frame at `0x42420000`,
unused by the dispatcher.

Some blocks might jump to several different successors, depending on a
conditional branch: for instance, in the following block, if 
`AL != BL`, the next block executed is 0x43, otherwise it is 0x35.

```
00000144 8a 44 24 10     MOV        AL,byte ptr [RSP + offset DAT_42420010]
00000148 8a 5c 24 11     MOV        BL,byte ptr [RSP + offset DAT_42420011]
0000014c 38 d8           CMP        AL,BL
0000014e 48 c7 c4        MOV        RSP,0x42420000
         00 00 42 42
00000155 48 c7 c0        MOV        RAX,0x43
         43 00 00 00
0000015c 48 c7 c3        MOV        RBX,0x35
         35 00 00 00
00000163 48 0f 45 c3     CMOVNZ     RAX,RBX
00000167 48 89 84        MOV        qword ptr [RSP + offset DAT_42420088],RAX
         24 88 00 
         00 00
0000016f 48 c7 c0        MOV        RAX,0xf
         0f 00 00 00
00000176 0f 05           SYSCALL
```

The principal difficulty is that the logic is interleaved between both
the code blocks and the values that are previously attributed to
registers before the execution of each block (that are stored in the
sigreturn frames). For instance, in the block above, RSP has
previously been set to `0xcafe1008` by `sigreturn` (the area mapped at
`0xcafe0000` is actually used as a "stack" for the obfuscated
program).

One possible way to reconstitute the control flow of the program is as
follows:
- associate each block to its sigreturn frame by identifying the RIP
  value of the sigreturn frame,
- emulate the "dispatcher" by replacing the sigreturns with direct
  jumps to the next block, handling carefully the conditionals.
  
In a nutshell, one can generate a new `program_deobf.bin` where the
blocks are of the form:
```
    mov r8, <r8_in_the_corresponding_sigreturn_frame>
    mov r9, <r9_in_the_corresponding_sigreturn_frame>
    ...
    mov rdi, <rdi_in_the_corresponding_sigreturn_frame>
    mov rsi, <rsi_in_the_corresponding_sigreturn_frame>
    ...
    [the code block]
    mov rax, <the_offset_of_the_successor>
    jmp rax
```

For blocks with conditionals, the final part is replaced with
```
    mov rax, <offset_successor1>
    mov rbx, <offset_successor2>
    j<cond> taken
    jmp rax
taken:
    jmp rbx
```

The blocks being shuffled and not in the same order as the
corresponding sigreturn frames, particular attention is required for
this step.

The full script to deobfuscate the program is available
[here](./src/deobf.py)

Then, the pseudo-code can more or less be reconstituted in a
decompiler. After googling a bit or asking our favorite LLM, we figure
out that the program encodes a 9x9 Suguru puzzle. The areas are
hardcoded in a 81-byte buffer `areas` whose bytes are equal to values
in 0-18. Each area is numbered, and a given square `(i,j)` belongs to
the area `N` if `areas[i*9+j] = N`. The constraints (already placed
numbers) are also hardcoded in another buffer.

After prompting the user for input, the program checks its validity
with respect to data concerning the grid. If the input is correct, it
is hashed with SHA512 and xored with a constant (the decryption
function is actually in the main binary), which prints the
flag. Otherwise, it calls another function that prints the "wrong
input" message.

The expected input is the numbers in the solved Suguru grid, as a
81-char long string. Suguru solvers using Z3 can easily be found on
github. 

The solver script is available [here](./src/solve.py)

After finding the (unique) solution:
`141253514235414232142323541235141232142323541231514132142323251351541434143232521`, we input it to the binary to get the flag.

```
$ ./pors
Enter your input: 141253514235414232142323541235141232142323541231514132142323251351541434143232521
[+] Congratulations! You can validate the challenge with this flag: CWTE{pr0gr4mm4t10n_0r13nt33_r3t0ur_s1gn4l}
```

**FLAG:** `CWTE{pr0gr4mm4t10n_0r13nt33_r3t0ur_s1gn4l}`. It means
"signal return oriented programming" in French, and thanks to a great
coincidence, "PORS" is also "SROP" in reverse :-)

from pwn import *
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import *

prog_size, program, srop_size, srop_frames = None, None, None, None

info("Parsing the program...")

with open("program.bin", "rb") as f:
    prog_size = u32(f.read(4))
    program = f.read(prog_size)
    srop_size = u32(f.read(4))
    srop_frames = f.read(srop_size)

frame_number = srop_size // 0xf8
    
parsed_frames = [SigreturnFrame(arch='amd64') for i in range(frame_number)]
block_indices = [0 for i in range(frame_number)]
inv_block_indices = [0 for i in range(frame_number)]

for i in range(frame_number):
    off = i*0xf8
    parsed_frames[i].r8 = u64(srop_frames[off + 0x28:off + 0x30])
    parsed_frames[i].r9 = u64(srop_frames[off + 0x30:off + 0x38])
    parsed_frames[i].r10 = u64(srop_frames[off + 0x38:off + 0x40])
    parsed_frames[i].r11 = u64(srop_frames[off + 0x40:off + 0x48])
    parsed_frames[i].r12 = u64(srop_frames[off + 0x48:off + 0x50])
    parsed_frames[i].r13 = u64(srop_frames[off + 0x50:off + 0x58])
    parsed_frames[i].r14 = u64(srop_frames[off + 0x58:off + 0x60])
    parsed_frames[i].r15 = u64(srop_frames[off + 0x60:off + 0x68])
    parsed_frames[i].rdi = u64(srop_frames[off + 0x68:off + 0x70])
    parsed_frames[i].rsi = u64(srop_frames[off + 0x70:off + 0x78])
    parsed_frames[i].rbp = u64(srop_frames[off + 0x78:off + 0x80])
    parsed_frames[i].rbx = u64(srop_frames[off + 0x80:off + 0x88])
    parsed_frames[i].rdx = u64(srop_frames[off + 0x88:off + 0x90])
    parsed_frames[i].rax = u64(srop_frames[off + 0x90:off + 0x98])
    parsed_frames[i].rcx = u64(srop_frames[off + 0x98:off + 0xa0])
    parsed_frames[i].rsp = u64(srop_frames[off + 0xa0:off + 0xa8])
    parsed_frames[i].rip = u64(srop_frames[off + 0xa8:off + 0xb0])
    block_indices[i] = (parsed_frames[i].rip - 0x13370000) // 0x50
    inv_block_indices[(parsed_frames[i].rip - 0x13370000) // 0x50] = i

code_blocks = [program[i*0x50:(i+1)*0x50] for i in range(frame_number)]

# print(code_blocks, block_indices)

info("Reconstituting the CFG...")

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

actual_blocks = []

for i in range(1, frame_number):
    b = code_blocks[i]
    before_mov_rsp = []
    successors = []
    calls = []
    cmov_condition = None
    
    found_mov_rsp = False
    for insn in md.disasm(b, 0x1337):
        if not found_mov_rsp:
            if insn.mnemonic.lower() == "mov" and insn.op_str.lower().startswith("rsp, 0x42420000"):
                found_mov_rsp = True
            elif insn.mnemonic.lower() == "jmp":
                calls = [insn.reg_name(insn.operands[0].reg)]
                break
            else:
                before_mov_rsp.append(f"{insn.mnemonic} {insn.op_str}")
        else:
            # Cherche valeurs de MOV vers RAX/RBX
            if insn.mnemonic.lower() == "mov":
                if (
                        len(insn.operands) == 2 and
                        insn.operands[0].type == X86_OP_MEM and
                        insn.operands[0].size == 8 and  # qword
                        insn.operands[0].mem.base != 0 and
                        insn.reg_name(insn.operands[0].mem.base) == "rsp" and
                        insn.operands[0].mem.disp == 0x88 
                ):
                    if cmov_condition == None:
                        successors = [insn.operands[1].imm]
                    break
                if insn.operands[0].type == X86_OP_REG and insn.operands[1].type == X86_OP_IMM:
                    reg = insn.reg_name(insn.operands[0].reg)
                    imm = insn.operands[1].imm
                    if reg in ("rax", "rbx"):
                        successors.append(imm)
            elif insn.mnemonic.lower().startswith("cmov"):
                cmov_condition = insn.mnemonic[4:]

    if successors == [] and calls == []:
        print(i, b)
    
    actual_blocks.append((('\n'.join(before_mov_rsp), successors, calls, cmov_condition, parsed_frames[inv_block_indices[i]])))

# print(actual_blocks)
info("Writing deobfuscated code...")

new_blocks = []
block_size = 0x200

for i in range(frame_number-1):
    ab = actual_blocks[i]
    code = ab[0]
    successors = ab[1]
    calls = ab[2]
    cond = ab[3]
    frame = ab[4]
    new_asm = ''
    new_asm += 'mov r8, 0x%x\n' % frame.r8
    new_asm += 'mov r9, 0x%x\n' % frame.r9
    new_asm += 'mov r10, 0x%x\n' % frame.r10
    new_asm += 'mov r11, 0x%x\n' % frame.r11
    new_asm += 'mov r12, 0x%x\n' % frame.r12
    new_asm += 'mov r13, 0x%x\n' % frame.r13
    new_asm += 'mov r14, 0x%x\n' % frame.r14
    new_asm += 'mov r15, 0x%x\n' % frame.r15
    new_asm += 'mov rdi, 0x%x\n' % frame.rdi
    new_asm += 'mov rsi, 0x%x\n' % frame.rsi
    new_asm += 'mov rbp, 0x%x\n' % frame.rbp
    new_asm += 'mov rbx, 0x%x\n' % frame.rbx
    new_asm += 'mov rdx, 0x%x\n' % frame.rdx
    new_asm += 'mov rax, 0x%x\n' % frame.rax
    new_asm += 'mov rcx, 0x%x\n' % frame.rcx
    new_asm += code
    if len(successors) == 1:
        new_asm += '\n'
        new_asm += 'mov rax, 0x%x\n' % ((block_indices[successors[0]+1] - 1) * block_size + 0x10)
        new_asm += 'jmp rax'
    elif len(successors) == 2:
        new_asm += '\n'
        new_asm += 'mov rax, 0x%x\n' % ((block_indices[successors[0]+1] - 1) * block_size + 0x10)
        new_asm += 'mov rbx, 0x%x\n' % ((block_indices[successors[1]+1] - 1) * block_size + 0x10)
        new_asm += 'j%s taken\n' % cond
        new_asm += 'jmp rax\n'
        new_asm += 'taken:\n'
        new_asm += 'jmp rbx'
    elif len(calls) == 1:
        new_asm += 'call %s' % (calls[0])
    else:
        print("oh no")
        exit(1)

    new_block = asm(new_asm, vma=0, arch='amd64')
    new_block += b'\xcc'*(block_size - len(new_block))
    new_blocks.append(new_block)

final_code = b'' # asm("mov esp, 0xcafe0008")
final_code += b'\x90'*(0x10 - len(final_code))
final_code += b''.join(new_blocks)
    
open("program_deobf.bin", "wb").write(final_code)

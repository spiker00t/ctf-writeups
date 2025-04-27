from z3 import *

blocks = []
final_blocks = []
cur = ''

# parses each block, delimited by the calls to the circuits

with open('to_parse.txt', 'r') as f:
    finished = False
    for line in f.readlines():
        if "call" in line:
            function = line.split('call   ')[1].split(' <')[0]
            if function == '200a0':
                # corresponds to timed_read
                final_blocks.append(cur)
            else:
                # logic circuit
                blocks.append((function, cur))
            cur = ''
        else:
            cur += line

parsed_blocks = []
reading_flag = False
reading_output = False
char_flag = None
bit = 0

flag_bits_in_memory = {}
global_vals = set()

for i in range(len(blocks)):
    # for each block, we track its inputs and outputs.
    b = blocks[i]
    function = b[0]
    inputs = {}
    regs = {}
    outputs = []
    first_output = 0
    used_output = False
    for line in b[1].split('\n'):         
        if ',BYTE PTR [rax' in line:
            # read some input byte
            offset = line.split(',BYTE PTR [rax')[1]
            if offset[0] == ']':
                char_flag = 0
            else:
                char_flag = eval(offset.split('+')[1].split(']')[0])
            reading_flag = True
            bit = 0
            
        elif reading_flag and 'shr' in line:
            # input bit
            bit = eval(line.split(',')[-1])
            
        elif reading_flag and 'and' in line:
            # & 1 => effectively read the input bit
            reading_flag = False
            if "arg1" not in inputs:
                inputs["arg1"] = ('flag', 8*char_flag+bit)
                inputs["narg1"] = ('not flag', 8*char_flag+bit)
            elif "arg2" not in inputs:
                inputs["arg2"] = ('flag', 8*char_flag+bit)
                inputs["narg2"] = ('not flag', 8*char_flag+bit)
            elif "arg3" not in inputs:
                inputs["arg3"] = ('flag', 8*char_flag+bit)
                inputs["narg3"] = ('not flag', 8*char_flag+bit)
            else:
                inputs["arg4"] = ('flag', 8*char_flag+bit)
                inputs["narg4"] = ('not flag', 8*char_flag+bit)
                
        elif ',BYTE PTR [rbp-' in line:
            # when we reuse a stored flag bit
            offset = line.split(',BYTE PTR [rbp-')[1]
            offset = eval(line.split('rbp-')[1].split(']')[0])
            (char_flag, bit) = flag_bits_in_memory[offset]
            if "arg1" not in inputs:
                inputs["arg1"] = ('flag', 8*char_flag+bit)
                inputs["narg1"] = ('not flag', 8*char_flag+bit)
            elif "arg2" not in inputs:
                inputs["arg2"] = ('flag', 8*char_flag+bit)
                inputs["narg2"] = ('not flag', 8*char_flag+bit)
            elif "arg3" not in inputs:
                inputs["arg3"] = ('flag', 8*char_flag+bit)
                inputs["narg3"] = ('not flag', 8*char_flag+bit)
            else:
                inputs["arg4"] = ('flag', 8*char_flag+bit)
                inputs["narg4"] = ('not flag', 8*char_flag+bit)
                
        elif 'sub' in line and '0x100' in line:
            # sub 0x100 is encountered before an output location
            reading_output = True
            used_output = False
            first_output = 1 - first_output
            
        elif 'mov    BYTE PTR' in line and '0x0' not in line:
            # for flag bits that are reused later
            offset = eval(line.split('rbp-')[1].split(']')[0])
            flag_bits_in_memory[offset] = (char_flag, bit)
            
        elif 'mov    QWORD PTR [rbp-' in line and reading_output:
            # we store the corresponding output location
            offset = eval(line.split('rbp-')[1].split(']')[0])
            to_define = False
            for b in blocks[i+1:]:
                if '[rbp-%s]' % hex(offset) in b[1]:
                    to_define = True
            for b in final_blocks:
                if '[rbp-%s]' % hex(offset) in b:
                    to_define = True
            if not to_define:
                continue
            outputs.append(offset)
            used_output = True
            reading_output = False
            
        elif 'clflush' in line and reading_output and not used_output:
            # for optimization, in some cases the outputs are not
            # written to memory but stored in a register until
            # their next use.
            reading_output = False
            reg = line.split('BYTE PTR [')[1].split(']')[0]
            outputs.append(reg)
            
        elif ',QWORD PTR [rbp-' in line:
            # we look for inputs coming from the outputs of other circuits (global_vals)
            offset = line.split(',QWORD PTR [rbp-')[1]
            offset = eval(line.split('rbp-')[1].split(']')[0])
            reg = line.split(',QWORD PTR [rbp-')[0].split('mov    ')[1]
            if offset in global_vals:
                if reg == 'rdi':
                    inputs["narg1"] = ('global', offset)
                if reg == 'rsi':
                    inputs["arg1"] = ('global', offset)
                if reg == 'rdx':
                    inputs["narg2"] = ('global', offset)
                if reg == 'rcx':
                    inputs["arg2"] = ('global', offset)
                if reg == 'r8':
                    inputs["narg3"] = ('global', offset)
                if reg == 'r9':
                    inputs["arg3"] = ('global', offset)
                else:
                    regs[reg] = ('global', offset)
                    
        elif 'mov    QWORD PTR [rsp' in line:
            # the fourth input is stored in the stack 
            offset = line.split('mov    QWORD PTR [rsp')[1]
            if offset[0] == ']':
                offset = 0
            else:
                offset = eval(offset.split('+')[1].split(']')[0])
            if offset > 8:
                continue
            else:
                reg = line.split(',')[-1]
                arg = "narg4" if offset == 0 else "arg4"
                if arg not in inputs:
                    if reg in regs:
                        inputs[arg] = regs[reg]
                    else:
                        inputs[arg] = ('external', reg)
            
    for x in outputs:
        global_vals.add(x)
    parsed_blocks.append((function, inputs, outputs))

final_outs = []
effective_out = 1

for b in final_blocks:
    # we only keep the output bits, not the ones for the checksums
    if effective_out:
        final_outs.append(eval(b.split('QWORD PTR [rbp-')[1].split(']')[0]))
    effective_out = 1-effective_out
        
def ev(inp, out, reg):
    if inp[0] == 'flag':
        return flag_bits[inp[1]]
    elif inp[0] == 'not flag':
        return 1 - flag_bits[inp[1]]
    elif inp[0] == 'global':
        return out[inp[1]]
    elif inp[0] == 'external':
        return reg[inp[1]]
        
    
def formula1(inp, out, reg):
    res = 0
    res = res | (ev(inp["narg1"], out, reg) & ev(inp["narg2"], out, reg) & ev(inp["arg4"], out, reg))
    res = res | (ev(inp["narg1"], out, reg) & ev(inp["narg2"], out, reg) & ev(inp["arg3"], out, reg))
    res = res | (ev(inp["narg1"], out, reg) & ev(inp["arg2"], out, reg) & ev(inp["narg3"], out, reg) & ev(inp["narg4"], out, reg))
    res = res | (ev(inp["arg1"], out, reg) & ev(inp["narg2"], out, reg) & ev(inp["narg3"], out, reg) & ev(inp["narg4"], out, reg))
    res = res | (ev(inp["arg1"], out, reg) & ev(inp["arg2"], out, reg) & ev(inp["arg4"], out, reg))
    res = res | (ev(inp["arg1"], out, reg) & ev(inp["arg2"], out, reg) & ev(inp["arg3"], out, reg))
    return res

def formula2(inp, out, reg):
    res = 0
    res = res | (ev(inp["narg1"], out, reg) & ev(inp["narg2"], out, reg) & ev(inp["arg3"], out, reg) & ev(inp["arg4"], out, reg))
    res = res | (ev(inp["narg1"], out, reg) & ev(inp["arg2"], out, reg) & ev(inp["narg4"], out, reg))
    res = res | (ev(inp["narg1"], out, reg) & ev(inp["arg2"], out, reg) & ev(inp["narg3"], out, reg))
    res = res | (ev(inp["arg1"], out, reg) & ev(inp["narg2"], out, reg) & ev(inp["narg4"], out, reg))
    res = res | (ev(inp["arg1"], out, reg) & ev(inp["narg2"], out, reg) & ev(inp["narg3"], out, reg))
    res = res | (ev(inp["arg1"], out, reg) & ev(inp["arg2"], out, reg) & ev(inp["arg3"], out, reg) & ev(inp["arg4"], out, reg))
    return res

def formula3(inp, out, reg):
    res = 0
    res = res | (ev(inp["narg1"], out, reg) & ev(inp["narg2"], out, reg) & ev(inp["arg4"], out, reg))
    res = res | (ev(inp["narg1"], out, reg) & ev(inp["narg2"], out, reg) & ev(inp["narg3"], out, reg))
    res = res | (ev(inp["narg1"], out, reg) & ev(inp["arg2"], out, reg) & ev(inp["arg3"], out, reg) & ev(inp["narg4"], out, reg))
    res = res | (ev(inp["arg1"], out, reg) & ev(inp["narg2"], out, reg) & ev(inp["arg3"], out, reg) & ev(inp["narg4"], out, reg))
    res = res | (ev(inp["arg1"], out, reg) & ev(inp["arg2"], out, reg) & ev(inp["arg4"], out, reg))
    res = res | (ev(inp["arg1"], out, reg) & ev(inp["arg2"], out, reg) & ev(inp["narg3"], out, reg))
    return res

def formula4(inp, out, reg):
    res = 0
    res = res | (ev(inp["narg1"], out, reg) & ev(inp["narg2"], out, reg) & ev(inp["narg3"], out, reg) & ev(inp["narg4"], out, reg))
    res = res | (ev(inp["narg1"], out, reg) & ev(inp["arg2"], out, reg) & ev(inp["arg4"], out, reg))
    res = res | (ev(inp["narg1"], out, reg) & ev(inp["arg2"], out, reg) & ev(inp["arg3"], out, reg))
    res = res | (ev(inp["arg1"], out, reg) & ev(inp["narg2"], out, reg) & ev(inp["arg4"], out, reg))
    res = res | (ev(inp["arg1"], out, reg) & ev(inp["narg2"], out, reg) & ev(inp["arg3"], out, reg))
    res = res | (ev(inp["arg1"], out, reg) & ev(inp["arg2"], out, reg) & ev(inp["narg3"], out, reg) & ev(inp["narg4"], out, reg))
    return res

def formula5(inp, out, reg):
    res = 0
    res = res | (ev(inp["narg1"], out, reg) & ev(inp["narg2"], out, reg) & ev(inp["arg3"], out, reg) & ev(inp["narg4"], out, reg))
    res = res | (ev(inp["narg1"], out, reg) & ev(inp["arg2"], out, reg) & ev(inp["arg4"], out, reg))
    res = res | (ev(inp["narg1"], out, reg) & ev(inp["arg2"], out, reg) & ev(inp["narg3"], out, reg))
    res = res | (ev(inp["arg1"], out, reg) & ev(inp["narg2"], out, reg) & ev(inp["arg4"], out, reg))
    res = res | (ev(inp["arg1"], out, reg) & ev(inp["narg2"], out, reg) & ev(inp["narg3"], out, reg))
    res = res | (ev(inp["arg1"], out, reg) & ev(inp["arg2"], out, reg) & ev(inp["arg3"], out, reg) & ev(inp["narg4"], out, reg))
    return res

def formula6(inp, out, reg):
    res = 0
    res = res | (ev(inp["narg1"], out, reg) & ev(inp["narg2"], out, reg) & ev(inp["narg4"], out, reg))
    res = res | (ev(inp["narg1"], out, reg) & ev(inp["narg2"], out, reg) & ev(inp["narg3"], out, reg))
    res = res | (ev(inp["narg1"], out, reg) & ev(inp["arg2"], out, reg) & ev(inp["arg3"], out, reg) & ev(inp["arg4"], out, reg))
    res = res | (ev(inp["arg1"], out, reg) & ev(inp["narg2"], out, reg) & ev(inp["arg3"], out, reg) & ev(inp["arg4"], out, reg))
    res = res | (ev(inp["arg1"], out, reg) & ev(inp["arg2"], out, reg) & ev(inp["narg4"], out, reg))
    res = res | (ev(inp["arg1"], out, reg) & ev(inp["arg2"], out, reg) & ev(inp["narg3"], out, reg))
    return res

def nxor(inp, out, reg):
    return (1 - (ev(inp["arg1"], out, reg) ^ ev(inp["arg2"], out, reg)))

def xor(inp, out, reg):
    return ev(inp["arg1"], out, reg) ^ ev(inp["arg2"], out, reg)

def assign_output(out, val):
    if isinstance(out,str):
        reg_values[out] = val
    else:
        out_values[out] = val
        
target = 0x1234567890abcdef
target_bits = [(target >> i) & 1 for i in range(64)]

flag_bits = [BitVec('flag%d'%i, 1) for i in range(64)]

# flag = 0xaaaabbbbccccdddd
# flag_bits = [(flag >> i) & 1 for i in range(64)]

out_values = {}
reg_values = {}

for (function, inputs, outputs) in parsed_blocks:
    if function == '211f0':
        assign_output(outputs[1], formula1(inputs, out_values, reg_values))
        assign_output(outputs[0], 1 - formula1(inputs, out_values, reg_values))
    elif function == '21510':
        assign_output(outputs[1], formula2(inputs, out_values, reg_values))
        assign_output(outputs[0], 1 - formula2(inputs, out_values, reg_values))
    elif function == '20ed0':
        assign_output(outputs[1], formula3(inputs, out_values, reg_values))
        assign_output(outputs[0], 1 - formula3(inputs, out_values, reg_values))
    elif function == '20bb0':
        assign_output(outputs[1], formula4(inputs, out_values, reg_values))
        assign_output(outputs[0], 1 - formula4(inputs, out_values, reg_values))
    elif function == '20890':
        assign_output(outputs[1], formula5(inputs, out_values, reg_values))
        assign_output(outputs[0], 1 - formula5(inputs, out_values, reg_values))
    elif function == '200d0':
        assign_output(outputs[1], formula6(inputs, out_values, reg_values))
        assign_output(outputs[0], 1 - formula6(inputs, out_values, reg_values))
    elif function == '21830':
        assign_output(outputs[1], nxor(inputs, out_values, reg_values))
        assign_output(outputs[0], 1 - nxor(inputs, out_values, reg_values))
    elif function == '21a90':
        assign_output(outputs[1], xor(inputs, out_values, reg_values))
        assign_output(outputs[0], 1 - xor(inputs, out_values, reg_values))
    elif function == '20650' or function == '203f0':
        for i in range(0,len(outputs)//2):
            assign_output(outputs[2*i], ev(inputs["narg1"], out_values, reg_values))
            assign_output(outputs[2*i+1], ev(inputs["arg1"], out_values, reg_values))
    else:
        print('Oops, I forgotten function %s' % function)

        
res_bits = [out_values[i] for i in final_outs]

s = Solver()

for i in range(64):
    s.add(res_bits[i] == target_bits[i])

s.check()
m = s.model()

flag = 0

for i in range(64):
    flag |= (m[flag_bits[i]].as_long() << i)

print(hex(flag))

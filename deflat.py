from barf.barf import BARF
from settings import opcode
import angr
from angr.state_plugins.inspect import BP_BEFORE
from angr.sim_options import LAZY_SOLVES
import pyvex
import claripy
import struct
import sys


class Deflat:
    def __init__(self, filename):
        self.filename = filename
        self.barf = BARF(filename)
        self.base_addr = self.barf.binary.entry_point >> 12 << 12
        self.b = angr.Project(filename, load_options={'auto_load_libs': False, 'main_opts': {'custom_base_addr': 0}})
        self.cfg = self.barf.recover_cfg(start=start)
        self.block = self.cfg.basic_blocks
        self.prologue = start

        self.main_dispatcher = self.cfg.find_basic_block(self.prologue).direct_branch
        self.retn = None
        self.pre_dispatcher = None
        self.modify_value = None

    def get_retn_predispatcher(self, cfg):
        retn, pre_dispatcher = None, None
        for block in cfg.basic_blocks:
            if len(block.branches) == 0 and block.direct_branch is None:
                retn = block.start_address
            elif block.direct_branch == self.main_dispatcher:
                pre_dispatcher = block.start_address
        return retn, pre_dispatcher

    def get_relevant_nop_blocks(self, cfg):
        relevant_blocks = []
        nop_blocks = []
        for block in cfg.basic_blocks:
            if block.direct_branch == self.pre_dispatcher and len(block.instrs) != 1:
                relevant_blocks.append(block.start_address)
            elif block.start_address != self.prologue and block.start_address != self.retn:
                nop_blocks.append(block)
        return relevant_blocks, nop_blocks

    def statement_inspect(state):
        global modify_value
        expressions = state.scratch.irsb.statements[state.inspect.statement].expressions
        if len(expressions) != 0 and isinstance(expressions[0], pyvex.expr.ITE):
            state.scratch.temps[expressions[0].cond.tmp] = modify_value
            state.inspect._breakpoints['statement'] = []

    def symbolic_execution(self, start_addr, hook_addr=None, modify=None, inspect=False):
        if hook_addr != None:
            self.b.hook(hook_addr, self.retn_procedure, length=5)
        if modify != None:
            self.modify_value = modify
        state = self.b.factory.blank_state(addr=start_addr, remove_options={LAZY_SOLVES})
        if inspect:
            state.inspect.b('statement', when=BP_BEFORE, action=self.statement_inspect)
        p = self.b.factory.path(state)
        succ = p.step()
        while succ.successors[0].addr not in self.relevants:
            succ = succ.successors[0].step()
        return succ.successors[0].addr

    def retn_procedure(state):
        global b
        ip = state.se.eval(state.regs.ip)
        b.unhook(ip)
        return

    def fill_nop(data, start, end):
        global opcode
        for i in range(start, end):
            data[i] = opcode['nop']

    def fill_jmp_offset(data, start, offset):
        jmp_offset = struct.pack('<i', offset)
        for i in range(4):
            data[start + i] = jmp_offset[i]

    def create(self, start):
        self.retn, self.pre_dispatcher = self.get_retn_predispatcher(self.cfg)
        relevant_blocks, nop_blocks = self.get_relevant_nop_blocks(self.cfg)
        print('*******************relevant blocks************************')
        print('prologue:%#x' % start)
        print('main_dispatcher:%#x' % self.main_dispatcher)
        print('pre_dispatcher:%#x' % self.pre_dispatcher)
        print('retn:%#x' % self.retn)
        print('relevant_blocks:', [hex(addr) for addr in relevant_blocks])
        return relevant_blocks, nop_blocks

    def symbolic_execution_main(self, relevant_blocks):
        relevants = relevant_blocks
        relevants.append(self.prologue)
        relevants_without_retn = list(relevants)
        relevants.append(self.retn)
        flow = {}
        for parent in relevants:
            flow[parent] = []
        self.modify_value = None
        patch_instrs = {}
        for relevant in relevants_without_retn:
            print('-------------------dse %#x---------------------' % relevant)
            block = self.cfg.find_basic_block(relevant)
            has_branches = False
            hook_addr = None
            for ins in block.instrs:
                if ins.mnemonic.startswith('cmov'):
                    patch_instrs[relevant] = ins
                    has_branches = True
                elif ins.mnemonic.startswith('call'):
                    hook_addr = ins.address
            if has_branches:
                flow[relevant].append(self.symbolic_execution(relevant, hook_addr, claripy.BVV(1, 1), True))
                flow[relevant].append(self.symbolic_execution(relevant, hook_addr, claripy.BVV(0, 1), True))
            else:
                flow[relevant].append(self.symbolic_execution(relevant, hook_addr))
        return flow

    def patch(self, flow):
        print('************************patch*****************************')
        flow.pop(self.retn)
        origin = open(filename, 'rb')
        origin_data = list(origin.read())
        origin.close()
        recovery = open(filename + '.recovered', 'wb')
        for nop_block in self.nop_blocks:
            self.fill_nop(origin_data, nop_block.start_address - self.base_addr, nop_block.end_address - self.base_addr + 1)
        for (parent, childs) in flow.items():
            if len(childs) == 1:
                last_instr = self.cfg.find_basic_block(parent).instrs[-1]
                file_offset = last_instr.address - self.base_addr
                origin_data[file_offset] = opcode['jmp']
                file_offset += 1
                self.fill_nop(origin_data, file_offset, file_offset + last_instr.size - 1)
                self.fill_jmp_offset(origin_data, file_offset, childs[0] - last_instr.address - 5)
            else:
                instr = self.patch_instrs[parent]
                file_offset = instr.address - self.base_addr
                self.fill_nop(origin_data, file_offset, self.cfg.find_basic_block(parent).end_address - self.base_addr + 1)
                origin_data[file_offset] = opcode['j']
                origin_data[file_offset + 1] = opcode[instr.mnemonic[4:]]
                self.fill_jmp_offset(origin_data, file_offset + 2, childs[0] - instr.address - 6)
                file_offset += 6
                origin_data[file_offset] = opcode['jmp']
                self.fill_jmp_offset(origin_data, file_offset + 1, childs[1] - (instr.address + 6) - 5)

    def main(self, start):
        relevant_blocks, nop_blocks = self.create(start)
        flow = self.symbolic_execution_main(relevant_blocks)
        print('************************flow******************************')
        for (k, v) in flow.items():
            print('%#x:' % k, [hex(child) for child in v])
        self.patch(flow)
        recovery.write(''.join(origin_data))
        recovery.close()
        print('Successful! The recovered file: %s' % (filename + '.recovered'))


if __name__ == '__main__':
    filename = "check_passwd_flat"
    start = 0x400530
    deflat = Deflat(filename)
    deflat.main(start)



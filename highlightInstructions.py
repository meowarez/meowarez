import idautils
import idc

def main():
    allFuncs = idautils.Functions()

    for func in allFuncs:
        # Get a list of unanalyzed subfunctions
        dism_addr = list(idautils.FuncItems(func))
        for ea in dism_addr:
            '''
                https://www.hex-rays.com/products/ida/support/sdkdoc/group__o__.html

                const optype_t     o_void = 0      No Operand.
                const optype_t     o_reg = 1       General Register (al,ax,es,ds...).
                const optype_t     o_mem = 2       Direct Memory Reference (DATA).
                const optype_t     o_phrase = 3    Memory Ref [Base Reg + Index Reg].
                const optype_t     o_displ = 4     Memory Reg [Base Reg + Index Reg + Displacement].
                const optype_t     o_imm = 5       Immediate Value.

                idc.set_color(ea, CIC_ITEM, 0xBBGGRR)
            '''

            # Highlight based on mnemonic
            mnemonic = idc.print_insn_mnem(ea)
            if mnemonic == 'call':
                idc.set_color(ea, CIC_ITEM, 0xc7c7ff)
            elif mnemonic == 'xor':
                # Zeroing out register
                if idc.print_operand(ea, 0) == idc.print_operand(ea, 1):
                    idc.set_color(ea, CIC_ITEM, 0xAAAAAA)
                # Encode/Decode?
                else:
                    idc.set_color(ea, CIC_ITEM, 0xFFFF00)
            '''
            elif mnemonic == 'inc':
                idc.set_color(ea, CIC_ITEM, 0x000000)
            elif mnemonic == 'dec':
                idc.set_color(ea, CIC_ITEM, 0x000000)
            elif mnemonic == '':
                idc.set_color(ea, CIC_ITEM, 0x000000)
            elif mnemonic == '':
                idc.set_color(ea, CIC_ITEM, 0x000000)
            elif mnemonic == '':
                idc.set_color(ea, CIC_ITEM, 0x000000)
            '''

main()

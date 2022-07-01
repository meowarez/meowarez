# REcon 2022 Software Deobfuscation Techniques

import sys

from miasm.analysis.binary import Container
from miasm.analysis.data_flow import DeadRemoval, \
    merge_blocks, remove_empty_assignblks
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.expression.simplifications import expr_simp


#def write_graph(output_file, ira_cfg):
#    open(output_file, "w").write(ira_cfg.dot())


# check args
if len(sys.argv) < 4:
    print("[x] Syntax: {} <file> <architecture> <addr>".format(sys.argv[0]))
    sys.exit()

# parse stdin
file_path = sys.argv[1]
architecture = sys.argv[2]
start_addr = int(sys.argv[3], 16)

# init symbol table
loc_db = LocationDB()
# read binary file
container = Container.from_stream(open(file_path, 'rb'), loc_db)
# get CPU abstraction
machine = Machine(architecture)
# disassembly engine
mdis = machine.dis_engine(container.bin_stream, loc_db=loc_db)

# retrieve all basic blocks starting at start_addr
asm_cfg = mdis.dis_multiblock(start_addr)

# init intermediate representation analysis (IRA) / lifter class
lifter = machine.lifter_model_call(mdis.loc_db)

# translate asm_cfg into ira_cfg
ira_cfg = lifter.new_ircfg_from_asmcfg(asm_cfg)

# get head of function
head = mdis.loc_db.get_offset_location(start_addr)

# write IRA graph before simplifications
#write_graph("before_simp.dot", ira_cfg)

# set entry point
entry_points = {mdis.loc_db.get_offset_location(start_addr)}

# dead code elimination
deadrm = DeadRemoval(lifter)

# TODO: implement fix-point iteration
ira_cfg.simplify(expr_simp)
deadrm(ira_cfg)
remove_empty_assignblks(ira_cfg)
merge_blocks(ira_cfg, entry_points)

# write IRA graph after simplifications
#write_graph("after_simp.dot", ira_cfg)

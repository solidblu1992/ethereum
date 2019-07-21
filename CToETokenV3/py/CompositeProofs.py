from tinydb import TinyDB
from py_ecc import bn128
from random import SystemRandom
from OneBitRangeProof import H_from_address, ExtractCommitments

#Open DB
db = TinyDB('client_db.json')
tbl = db.table('commitments')
data = tbl.all()
assert(len(data) > 0)

#Index private commitments and sort by hidden value bit
raw_commitments = data[0]['private']
pc, index = zip(*sorted(zip(raw_commitments, list(range(0, len(raw_commitments))))))

max_index = len(pc)-1
one_start_index = 0
while(pc[one_start_index][0] == 0):
    one_start_index += 1

#Test commitment build
sr = SystemRandom()
target_bits = 64
v = sr.randint(1*10**15, 1*10**18)
asset_address = 0

indices = [0]*target_bits

total_bf = 0
v_test = 0
bit_flag = (1 << target_bits-1)
for i in range(0, target_bits):
    total_bf = total_bf*2 % bn128.curve_order
    v_test *= 2

    if bit_flag & v == 0:
        #Pick random zero commitment index
        indices[i] = index[sr.randint(0, one_start_index-1)]
    else:
        #Pick random one commitment index
        indices[i] = index[sr.randint(one_start_index, max_index)]

    #Update total_bf
    v_test += raw_commitments[indices[i]][0]
    total_bf = total_bf + raw_commitments[indices[i]][1] % bn128.curve_order 
    bit_flag >>= 1

#Test commitment build
C_expected = bn128.add(bn128.multiply(bn128.G1, total_bf), bn128.multiply(H_from_address(asset_address), v))
_, commitments = ExtractCommitments(bytes.fromhex(data[0]['data']))
C_out = None
for i in range(0, len(indices)):
    if bn128.is_inf(C_out):
        C_out = commitments[indices[i]]
        C_out = (bn128.FQ(C_out[0]), bn128.FQ(C_out[1]))
    else:
        C_out = bn128.add(C_out, C_out)
        C_out = bn128.add(C_out, commitments[indices[i]])

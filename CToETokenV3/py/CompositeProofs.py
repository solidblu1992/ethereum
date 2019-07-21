from tinydb import TinyDB
from py_ecc import bn128
from random import SystemRandom
from OneBitRangeProof import H_from_address, ExtractCommitments

#Build commitment out of many one-bit commitments
def BuildCommitmentPrivate(v, private_bit_commitments, target_bits=64):
    #Sort bit commitments
    pc, index = zip(*sorted(zip(private_bit_commitments, list(range(0, len(private_bit_commitments))))))

    #Find transition from commitments to 0 to commitments to 1
    one_start_index = 0
    while(pc[one_start_index][0] == 0):
        one_start_index += 1

    indices_zero = list(range(0, one_start_index))
    indices_one = list(range(one_start_index, len(pc)))

    #Build commitments
    sr = SystemRandom()

    indices = [0]*target_bits

    total_bf = 0
    bit_flag = (1 << target_bits-1)
    for i in range(0, target_bits):
        total_bf = total_bf*2 % bn128.curve_order

        #If out of indices, refresh pool
        if len(indices_zero) == 0 or len(indices_one) == 0:
            indices_zero = list(range(0, one_start_index))
            indices_one = list(range(one_start_index, len(pc)))

        if v & bit_flag == 0:
            #Pick random zero commitment index
            r = sr.randint(0, len(indices_zero)-1)
            indices[i] = index[indices_zero[r]]

            #Remove index from further choices
            indices_zero = indices_zero[:r] + indices_zero[r+1:]
        else:
            #Pick random one commitment index
            r = sr.randint(0, len(indices_one)-1)
            indices[i] = index[indices_one[r]]

            #Remove index from further choices
            indices_one = indices_one[:r] + indices_one[r+1:]

        #Update total_bf
        total_bf = total_bf + private_bit_commitments[indices[i]][1] % bn128.curve_order 
        bit_flag >>= 1

    return indices, total_bf

#Assemble
def BuildCommitmentPublic(public_bit_commitments, indices):
    C_out = None

    for i in range(0, len(indices)):
        if bn128.is_inf(C_out):
            C_out = public_bit_commitments[indices[i]]
            C_out = (bn128.FQ(C_out[0]), bn128.FQ(C_out[1]))
        else:
            C_out = bn128.add(C_out, C_out)
            C_out = bn128.add(C_out, public_bit_commitments[indices[i]])

    return C_out

if __name__ == "__main__":
    #Open DB
    db = TinyDB('client_db.json')
    tbl = db.table('commitments')
    data = tbl.all()
    assert(len(data) > 0)

    #Index private commitments and sort by hidden value bit
    v = 100
    asset_address = 0
    private_bit_commitments = data[0]['private']
    indices, total_bf = BuildCommitmentPrivate(v, private_bit_commitments, target_bits=64)
    C_expected = bn128.add(bn128.multiply(bn128.G1, total_bf), bn128.multiply(H_from_address(asset_address), v))
    print("Commitment Generated")
    print("asset_address = 0x" + asset_address.to_bytes(20, 'big').hex())
    print("value = " + str(v))
    print("bf = " + hex(total_bf)[2:])
    print("(" + C_expected[0].n.to_bytes(32, 'big').hex() + ",")
    print(C_expected[1].n.to_bytes(32, 'big').hex() + ")")
    print()

    #Test commitment build
    _, public_bit_commitments = ExtractCommitments(bytes.fromhex(data[0]['data']))
    C_out = BuildCommitmentPublic(public_bit_commitments, indices)
    print("Assembled Commitment")
    print("(" + C_out[0].n.to_bytes(32, 'big').hex() + ",")
    print(C_out[1].n.to_bytes(32, 'big').hex() + ")")
    print()

    #Do results match?
    print("Do they match?")
    print(bn128.eq(C_out, C_expected))

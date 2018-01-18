from ring_signatures import *
from ct import *
from stealth import *

class RingCT:
    ring_size = 0
    input_count = 0
    input_commitments = []
    output_pub_keys = []
    output_commitments = []
    signature = 0
    
    def __init__(self, ring_size, input_count, input_commitments,
                 output_pub_keys, output_commitments,
                 signature):
        self.ring_size = ring_size
        self.input_count = input_count
        self.input_commitments = input_commitments
        self.output_pub_keys = output_pub_keys
        self.output_commitments = output_commitments
        self.signature = signature

    def Sign(xk, xk_v, xk_bf, mixin_pub_keys, mixin_commitments,
             output_pub_keys, out_v, out_bf):
        import random

        #Check array dimensions
        input_count = len(xk)
        assert(input_count > 0)
        assert(len(xk) == input_count)
        assert(len(xk_v) == input_count)
        assert(len(xk_bf) == input_count)
        
        m = input_count + 1
        assert(len(mixin_pub_keys) % input_count == 0)
        assert(len(mixin_commitments) == len(mixin_pub_keys))
        n = len(mixin_pub_keys) // input_count + 1

        output_count = len(output_pub_keys)
        assert(output_count > 0)
        assert(len(out_v) == output_count)
        assert(len(out_bf) == output_count)

        #Check that input and output commitment values and blinding factors add up
        in_value = 0
        total_in_bf = 0
        out_value = 0
        total_out_bf = 0
        z = 0
        for i in range(0, input_count):
            in_value = in_value + xk_v[i]
            total_in_bf = (total_in_bf + xk_bf[i]) % Ncurve

        for i in range(0, output_count):
            out_value = out_value + out_v[i]
            total_out_bf = (total_out_bf + out_bf[i]) % Ncurve

        z = (total_in_bf + Ncurve - total_out_bf) % Ncurve

        assert(in_value == out_value)
        assert(z != 0) #blinding factors must add to a non-zero otherwise privacy is erased!

        #Pick slot for key vector
        indices = [random.randrange(0, n)] * m
        pub_keys = [None] * (m*n)
        input_commitments_new = [None]*((m-1)*n)
        priv_keys = [0] * (m)
        priv_keys[m-1] = 0

        #Fill in existing public / private keys and commitments
        for i in range(0, m-1):
            priv_keys[i] = xk[i]
            
            for j in range(0, n):
                if (j == indices[0]):
                    pub_keys[j*m+i] = multiply(G1, xk[i])
                    input_commitments_new[j*(m-1)+i] = add(multiply(H, xk_v[i]), multiply(G1, xk_bf[i]))
                elif(j > indices[0]):
                    pub_keys[j*m+i] = mixin_pub_keys[(j-1)*(m-1)+i]
                    input_commitments_new[j*(m-1)+i] = mixin_commitments[(j-1)*(m-1)+i]
                else:
                    pub_keys[j*m+i] = mixin_pub_keys[j*(m-1)+i]
                    input_commitments_new[j*(m-1)+i] = mixin_commitments[j*(m-1)+i]

        #Start building signature message
        hasher = sha3.keccak_256()

        for i in range(0, output_count):
            hasher.update(int_to_bytes32(output_pub_keys[i][0].n))
            hasher.update(int_to_bytes32(output_pub_keys[i][1].n))
            
        #Sum output commitments and finish building ring signature message
        output_commitments = [None]*output_count
        for i in range(0, output_count):
            output_commitments[i] = add(multiply(H, out_v[i]), multiply(G1, out_bf[i]))
            hasher.update(int_to_bytes32(output_commitments[i][0].n))
            hasher.update(int_to_bytes32(output_commitments[i][1].n))
            
        neg_total_out_commitment = neg(add(multiply(H, in_value), multiply(G1, total_out_bf)))
        msgHash = hasher.digest()

        #Sum up last column
        for j in range(0, n):
            s_point = None
            for i in range(0, m-1):
                #add public key
                s_point = add(s_point, pub_keys[j*m+i])

                #add public key's committed value
                if (j == indices[0]):
                    s_point = add(s_point, add(multiply(H, xk_v[i]), multiply(G1, xk_bf[i])))
                elif (j > indices[0]):
                    s_point = add(s_point, mixin_commitments[(j-1)*(m-1)+i])
                else:
                    s_point = add(s_point, mixin_commitments[j*(m-1)+i])

            #Subtract output commitments
            pub_keys[j*m+(m-1)] = add(s_point, neg_total_out_commitment)
                

        #Determine private key for last column
        priv_keys[m-1] = z
        for i in range(0, m-1):
            priv_keys[m-1] = (priv_keys[m-1] + xk[i]) % Ncurve

        return( RingCT(n, m-1,
                       input_commitments_new,
                       output_pub_keys,
                       output_commitments,
                       MLSAG.Sign_CompactPin_GenRandom(m, msgHash, priv_keys, indices, pub_keys)) )

    def Print(self):
        print("Ring CT Transaction")
        print("Inputs (PubKey1, PubKey2, ..., PubKeyM, sum(PubKeys)+sum(CommitedValue)-sum(OutputCommitments):")
        
        for j in range(0, self.ring_size):
            print("Key Vector " + str(j))
            
            for i in range(0, self.input_count+1):
                print(print_point(CompressPoint(self.signature.pub_keys[j*(self.input_count+1)+i])))

        print("-----")
        print("Outputs (PubKey, OutputCommitment)")
        for i in range(0, len(self.output_pub_keys)):
            print("Output " + str(i))
            print(print_point(CompressPoint(self.output_pub_keys[i])))
            print(print_point(CompressPoint(self.output_commitments[i])))
    

def RingCTTest(mixins = 3, inputs = 2, outputs = 2):
    import random

    #Generate private keys that we can use
    xk = []
    xk_c = []
    xk_v = []
    xk_bf = []
    xk_v_total = 0
    for i in range(0, inputs):
        xk = xk + [getRandom()]
        
        xk_v = xk_v + [random.randrange(0, 100)]
        xk_v_total = xk_v_total + xk_v[i]
        xk_v[i] = xk_v[i] * (10**16)
        
        xk_bf = xk_bf + [getRandom()]
        xk_c = xk_c + [add(multiply(G1, xk_bf[i]), multiply(H, xk_v[i]))]

    #Generate other mixable keys
    Pin = []
    Pin_c = []
    for i in range(0, inputs*mixins):
        Pin = Pin + [multiply(G1, getRandom())]
        Pin_c = Pin_c + [multiply(G1, getRandom())]

    #Generate outputs and dhe_points
    Pout = []
    dhe_point = []
    v_out = []
    bf_out = []
    c_out = []
    for i in range(0, outputs):
        Pout = Pout + [multiply(G1, getRandom())]
        dhe_point = dhe_point + [multiply(G1, getRandom())]

        if (i < (outputs - 1)):
            r = random.randrange(0, xk_v_total)
        else:
            r = xk_v_total
        
        xk_v_total = xk_v_total - r            
        v_out = v_out + [r*(10**16)]
        bf_out = bf_out + [getRandom()]
        c_out = c_out + [add(multiply(G1, bf_out[i]), multiply(H, v_out[i]))]

    #Generate Ring CT Token Instance    
    rct = RingCT.Sign(xk, xk_v, xk_bf, Pin, Pin_c, Pout, v_out, bf_out) 
    return rct



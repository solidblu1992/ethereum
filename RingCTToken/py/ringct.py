from ring_signatures import *
from ct import *
from stealth import *

def print_pub_keys(x, m, a, n):
    print("Pub Keys")
    for i in range(0, m-a):
        for j in range(0, n):
            if(x[j*m+i] != None):
                print(print_point(CompressPoint(x[j*m+i])))
            else:
                print("0x0")

        print("--")

class RingCT:
    ring_size = 0
    input_count = 0
    input_commitments = []
    output_transactions = []
    mlsag = 0
    
    def __init__(self, ring_size, input_count, input_commitments,
                 output_transactions, mlsag):
        self.ring_size = ring_size
        self.input_count = input_count
        self.input_commitments = input_commitments
        self.output_transactions = output_transactions
        self.mlsag = mlsag

    def Sign(xk, xk_v, xk_bf, mixin_transactions,
             output_transactions, out_v, out_bf):
        import random

        #Check array dimensions
        input_count = len(xk)
        assert(input_count > 0)
        assert(len(xk) == input_count)
        assert(len(xk_v) == input_count)
        assert(len(xk_bf) == input_count)
        
        m = input_count + 1
        assert(len(mixin_transactions) % input_count == 0)
        n = len(mixin_transactions) // input_count + 1

        output_count = len(output_transactions)
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

        #Fill in existing public / private keys and commitments
        for i in range(0, m-1):
            priv_keys[i] = xk[i]
            
            for j in range(0, n):
                if (j == indices[0]):
                    pub_keys[j*m+i] = multiply(G1, xk[i])
                    input_commitments_new[j*(m-1)+i] = add(multiply(H, xk_v[i]), multiply(G1, xk_bf[i]))
                elif(j > indices[0]):
                    pub_keys[j*m+i] = mixin_transactions[(j-1)*(m-1)+i].pub_key
                    input_commitments_new[j*(m-1)+i] = mixin_transactions[(j-1)*(m-1)+i].c_value
                else:
                    pub_keys[j*m+i] = mixin_transactions[j*(m-1)+i].pub_key
                    input_commitments_new[j*(m-1)+i] = mixin_transactions[j*(m-1)+i].c_value

        #Start building signature massage over output public keys, committed values, dhe points, and encrypted messages (both message and iv)
        hasher = sha3.keccak_256()
        subhashes = []
        for i in range(0, output_count):
            hasher.update(int_to_bytes32(output_count))
            hasher.update(int_to_bytes32(output_transactions[i].pub_key[0].n))
            hasher.update(int_to_bytes32(output_transactions[i].pub_key[1].n))

        subhashes = subhashes + [hasher.digest()]
        hasher = sha3.keccak_256()
        for i in range(0, output_count):
            hasher.update(int_to_bytes32(output_count))
            assert(eq(add(multiply(H, out_v[i]), multiply(G1, out_bf[i])),output_transactions[i].c_value)) 
            hasher.update(int_to_bytes32(output_transactions[i].c_value[0].n))
            hasher.update(int_to_bytes32(output_transactions[i].c_value[1].n))

        subhashes = subhashes + [hasher.digest()]
        hasher = sha3.keccak_256()
        for i in range(0, output_count):
            hasher.update(int_to_bytes32(output_count))
            hasher.update(int_to_bytes32(output_transactions[i].dhe_point[0].n))
            hasher.update(int_to_bytes32(output_transactions[i].dhe_point[1].n))

        subhashes = subhashes + [hasher.digest()]
        hasher = sha3.keccak_256()
        for i in range(0, output_count):
            hasher.update(int_to_bytes32(output_count))
            hasher.update(output_transactions[i].pc_encrypted_data.message)

        subhashes = subhashes + [hasher.digest()]
        hasher = sha3.keccak_256()
        for i in range(0, output_count):
            hasher.update(int_to_bytes32(output_count))
            hasher.update(int_to_bytes32(bytes_to_int(output_transactions[i].pc_encrypted_data.iv)))

        subhashes = subhashes + [hasher.digest()]
        hasher = sha3.keccak_256()
        for i in range(0, len(subhashes)):
            hasher.update(subhashes[i])

        msgHash = hasher.digest() 
        neg_total_out_commitment = neg(add(multiply(H, in_value), multiply(G1, total_out_bf)))
    
        #Sum up last column
        for j in range(0, n):
            #Subtract output commitments
            s_point = neg_total_out_commitment
            for i in range(0, m-1):
                #add public key
                s_point = add(s_point, pub_keys[j*m+i])
                s_point = add(s_point, input_commitments_new[j*(m-1)+i])

            #Store last column of public keys
            pub_keys[j*m+(m-1)] = s_point                

        #Determine private key for last column
        priv_keys[m-1] = z
        for i in range(0, m-1):
            priv_keys[m-1] = (priv_keys[m-1] + xk[i]) % Ncurve

        return( RingCT(n, m-1,
                       input_commitments_new,
                       output_transactions,
                       MLSAG.Sign_GenRandom(m, msgHash, priv_keys, indices, pub_keys)) )

    def Verify(self):
        #Assert array lengths
        if(self.input_count <= 0): return False
        output_count = len(self.output_transactions)
        if(output_count <= 0): return False
        
        n = self.ring_size
        m = self.input_count+1
        if(len(self.input_commitments) != n*(m-1)): return False        
        
        #Sum output commitments
        neg_total_output_commitment = None
        for i in range(0, len(self.output_transactions)):
            neg_total_output_commitment = add(neg_total_output_commitment, self.output_transactions[i].c_value)

        #negate it
        neg_total_output_commitment = neg(neg_total_output_commitment)

        #Verify that signature was built right
        for j in range(0, n):
            s_point = neg_total_output_commitment
            
            for i in range(0, m-1):
                s_point = add(s_point, self.mlsag.pub_keys[j*m+i])
                s_point = add(s_point, self.input_commitments[j*(m-1)+i])

            if (not eq(s_point, self.mlsag.pub_keys[j*m+(m-1)])): return False

        #Verify hash of output transactions: public keys, committed values, dhe_points, and encrypted data (message and iv)
        hasher = sha3.keccak_256()
        subhashes = []
        for i in range(0, output_count):
            hasher.update(int_to_bytes32(output_count))
            hasher.update(int_to_bytes32(self.output_transactions[i].pub_key[0].n))
            hasher.update(int_to_bytes32(self.output_transactions[i].pub_key[1].n))

        subhashes = subhashes + [hasher.digest()]
        hasher = sha3.keccak_256()
        for i in range(0, output_count):
            hasher.update(int_to_bytes32(output_count))
            hasher.update(int_to_bytes32(self.output_transactions[i].c_value[0].n))
            hasher.update(int_to_bytes32(self.output_transactions[i].c_value[1].n))

        subhashes = subhashes + [hasher.digest()]
        hasher = sha3.keccak_256()
        for i in range(0, output_count):
            hasher.update(int_to_bytes32(output_count))
            hasher.update(int_to_bytes32(self.output_transactions[i].dhe_point[0].n))
            hasher.update(int_to_bytes32(self.output_transactions[i].dhe_point[1].n))

        subhashes = subhashes + [hasher.digest()]
        hasher = sha3.keccak_256()
        for i in range(0, output_count):
            hasher.update(int_to_bytes32(output_count))
            hasher.update(self.output_transactions[i].pc_encrypted_data.message)

        subhashes = subhashes + [hasher.digest()]
        hasher = sha3.keccak_256()
        for i in range(0, output_count):
            hasher.update(int_to_bytes32(output_count))
            hasher.update(int_to_bytes32(bytes_to_int(self.output_transactions[i].pc_encrypted_data.iv)))

        subhashes = subhashes + [hasher.digest()]
        
        hasher = sha3.keccak_256()
        for i in range(0, len(subhashes)):
            hasher.update(subhashes[i])

        msgHash = hasher.digest()        
        if (msgHash != self.mlsag.msgHash): return False

        #Verify signature
        return self.mlsag.Verify()

    def Print(self):
        print("Ring CT Transaction")
        print("Inputs (PubKey1, C_Value1), ..., (PubKeyM, C_ValueM), {sum(PubKey1...M-1) + sum(C_Value1...M-1) - sum(C_Value_Out)}:")
        
        for j in range(0, self.ring_size):
            print("Key Vector " + str(j+1))
            
            for i in range(0, self.input_count+1):
                print(print_point(CompressPoint(self.mlsag.pub_keys[j*(self.input_count+1)+i])), end="")

                if (i < self.input_count):
                    print(", " + print_point(CompressPoint(self.input_commitments[j*(self.input_count) + i])))
                else:
                    print()

        print("-----")
        print("Outputs (PubKeyK, C_Value_OutK)")
        for i in range(0, len(self.output_transactions)):
            print("Output " + str(i+1))
            print(print_point(CompressPoint(self.output_transactions[i].pub_key)) + ", " + print_point(CompressPoint(self.output_transactions[i].c_value)))
            
    #Prints Ring CT parameters and signature in a format to be verified on the Ethereum blockchain
    def Print_Remix(self):
        output_count = len(self.output_transactions)
        
        #Print destination public keys
        print("Ring CT Remix Representation - for use with Send():")
        print("[", end="")
        for i in range(0, output_count):
            print("\"" + hex(self.output_transactions[i].pub_key[0].n) + "\",\n\"" + hex(self.output_transactions[i].pub_key[1].n) + "\"", end = "")

            if (i < (output_count-1)):
                print(",")
            else:
                print("],")

        #Print destination committed values
        print("[", end="")
        for i in range(0, output_count):
            print("\"" + hex(self.output_transactions[i].c_value[0].n) + "\",\n\"" + hex(self.output_transactions[i].c_value[1].n) + "\"", end = "")

            if (i < (output_count-1)):
                print(",")
            else:
                print("],")    

        #Print destination DHE Points
        print("[", end="")
        for i in range(0, output_count):
            print("\"" + hex(self.output_transactions[i].dhe_point[0].n) + "\",\n\"" + hex(self.output_transactions[i].dhe_point[1].n) + "\"", end = "")

            if (i < (output_count-1)):
                print(",")
            else:
                print("],")

        #Print encrypted data
        print("[", end="")
        for i in range(0, output_count):
            print("\"" + hex(bytes_to_int(self.output_transactions[i].pc_encrypted_data.message[:32])) + "\",")
            print("\"" + hex(bytes_to_int(self.output_transactions[i].pc_encrypted_data.message[32:])) + "\"", end = "")

            if (i < (output_count-1)):
                print(",")
            else:
                print("],")

        #Print encrypted data iv
        print("[", end="")
        for i in range(0, output_count):
            print("\"" + hex(bytes_to_int(self.output_transactions[i].pc_encrypted_data.iv)) + "\"", end = "")

            if (i < (output_count-1)):
                print(",")
            else:
                print("],")

        #Print key images (all of them)
        m = len(self.mlsag.key_images)
        print("[", end="")
        for i in range(0, m):
            print("\"" + hex(self.mlsag.key_images[i][0].n) + "\",\n\"" + hex(self.mlsag.key_images[i][1].n) + "\"", end = "")

            if (i < (m-1)):
                print(",")
            else:
                print("],")

        #Print public keys (except last column - calculated by contract)
        assert(len(self.mlsag.pub_keys) % m == 0)
        n = len(self.mlsag.pub_keys) // m
        print("[", end="")
        for j in range(0, n):
            for i in range(0, m-1):
                print("\"" + hex(self.mlsag.pub_keys[j*m+i][0].n) + "\",\n\"" + hex(self.mlsag.pub_keys[j*m+i][1].n) + "\"", end = "")

                if (i < (m-2)):
                    print(",")

            if (j < (n-1)):
                print(",")
            else:
                print("],")

        #Print signature (c1, s1, s2, ... snm)
        L = len(self.mlsag.signature)
        print("[", end="")
        for i in range(0, L-1):
            print("\"" + hex(self.mlsag.signature[i]) + "\",")

        print("\"" + hex(self.mlsag.signature[L-1]) + "\"]")

    def Print_MEW(self):
        output_count = len(self.output_transactions)
        
        #Print destination public keys
        print("Ring CT MEW Representation - for use with Send():")
        print("dest_pub_keys:")
        for i in range(0, output_count):
            print(hex(self.output_transactions[i].pub_key[0].n) + ",\n" + hex(self.output_transactions[i].pub_key[1].n), end = "")

            if (i < (output_count-1)):
                print(",")

        #Print destination committed values
        print("\n\nvalues:")
        for i in range(0, output_count):
            print(hex(self.output_transactions[i].c_value[0].n) + ",\n" + hex(self.output_transactions[i].c_value[1].n), end = "")

            if (i < (output_count-1)):
                print(",")

        #Print destination DHE Points
        print("\n\ndest_dhe_points:")
        for i in range(0, output_count):
            print(hex(self.output_transactions[i].dhe_point[0].n) + ",\n" + hex(self.output_transactions[i].dhe_point[1].n), end = "")

            if (i < (output_count-1)):
                print(",")

        #Print encrypted data
        print("\n\nencrypted_data:")
        for i in range(0, output_count):
            print(hex(bytes_to_int(self.output_transactions[i].pc_encrypted_data.message[:32])) + ",")
            print(hex(bytes_to_int(self.output_transactions[i].pc_encrypted_data.message[32:])), end = "")

            if (i < (output_count-1)):
                print(",")

        #Print encrypted data iv
        print("\n\niv:")
        for i in range(0, output_count):
            print(hex(bytes_to_int(self.output_transactions[i].pc_encrypted_data.iv)), end = "")

            if (i < (output_count-1)):
                print(",")

        #Print key images (all of them)
        m = len(self.mlsag.key_images)
        print("\n\nI:")
        for i in range(0, m):
            print(hex(self.mlsag.key_images[i][0].n) + ",\n" + hex(self.mlsag.key_images[i][1].n), end = "")

            if (i < (m-1)):
                print(",")

        #Print public keys (except last column - calculated by contract)
        assert(len(self.mlsag.pub_keys) % m == 0)
        n = len(self.mlsag.pub_keys) // m
        print("\n\ninput_pub_keys:")
        for j in range(0, n):
            for i in range(0, m-1):
                print(hex(self.mlsag.pub_keys[j*m+i][0].n) + ",\n" + hex(self.mlsag.pub_keys[j*m+i][1].n), end = "")

                if (i < (m-2)):
                    print(",")

            if (j < (n-1)):
                print(",")

        #Print signature (c1, s1, s2, ... snm)
        L = len(self.mlsag.signature)
        print("\n\nsignature:")
        for i in range(0, L-1):
            print(hex(self.mlsag.signature[i]) + ",")

        print(hex(self.mlsag.signature[L-1]))


def RingCTTest(mixins = 2, inputs = 2, outputs = 2):
    import random

    print("Testing Ring CT...")
    print("mixins = " + str(mixins) + ", inputs = " + str(inputs) + ", outputs = " + str(outputs))
    print("n = " + str(mixins+1) + ", m = " + str(inputs+1))
    print("--")

    #Generate private keys that we can use
    xk = []
    xk_c = []
    xk_v = []
    xk_bf = []
    xk_v_total = 0
    for i in range(0, inputs):
        xk = xk + [getRandom()]

        print("PubKey" + str(i) + ": " + print_point(CompressPoint(multiply(G1, xk[i]))))
        
        xk_v = xk_v + [random.randrange(0, 100)]
        xk_v_total = xk_v_total + xk_v[i]
        xk_v[i] = xk_v[i] * (10**16)
        
        xk_bf = xk_bf + [getRandom()]
        xk_c = xk_c + [add(multiply(G1, xk_bf[i]), multiply(H, xk_v[i]))]
        print("C_Value" + str(i) + ": " + print_point(CompressPoint(xk_c[i])))
        
    print("--")
    
    #Generate other mixable keys and commitments (and dhe_points/encrypted messages, but these are unused)
    mixin_tx = []
    for i in range(0, inputs*mixins):
        mixin_tx = mixin_tx + [StealthTransaction(multiply(G1, getRandom()), multiply(G1, getRandom()), multiply(G1, getRandom()), b"")]
        
    #Generate outputs and dhe_points
    out_tx = []
    v_out = []
    bf_out = []
    c_out = []
    for i in range(0, outputs):
        PubViewKey = multiply(G1, getRandom())
        PubSpendKey = multiply(G1, getRandom())

        if (i < (outputs - 1)):
            r = random.randrange(0, xk_v_total)
        else:
            r = xk_v_total
        
        xk_v_total = xk_v_total - r            
        v_out = v_out + [r*(10**16)]
        bf_out = bf_out + [getRandom()]
        c_out = c_out + [add(multiply(G1, bf_out[i]), multiply(H, v_out[i]))]

        out_tx = out_tx + [StealthTransaction.Generate(multiply(G1, getRandom()), multiply(G1, getRandom()), v_out[i], bf_out[i])]

    #Generate Ring CT Token Instance    
    rct = RingCT.Sign(xk, xk_v, xk_bf, mixin_tx, out_tx, v_out, bf_out) 
    return rct

#x = RingCTTest()
#x.Print_MEW()

def RingCTTest_Repeatable(input_count = 1, mixin_count = 2, outputs = 2, seed=0):
    import random
    print("Running RingCT Test (Repeatable)")
    print("input_count = 2")
    print("mixin_count = 2")
    print("ring_size = " + str(input_count+1) + " x " + str(mixin_count+1))
    print("================================")

    #Store View and Spend Keys
    pri_viewkey  = 0x26748d27140087af35b5523fbf4063a48e10277b7bb67379eae64b1e9bcdd49c
    pri_spendkey = 0x0657e10b4ecf56e94546357f35447ec39f6fee66c44c013aa55b54fcd6e4c340
    pub_viewkey  = multiply(G1, pri_viewkey)
    pub_spendkey = multiply(G1, pri_spendkey)

    #Pre-fetch random values for repeatable results
    r_index = 0
    r = []
    random.seed(seed)
    for i in range(0, 100):
        r = r + [getRandomUnsafe()]

    #Store Committed Values (each 0.01 ETH)
    xk_v = [1 * (10**16)] * (input_count*(mixin_count+1))
    xk_v_total = (1 * (10**16)) * (input_count)
    xk_bf = [0] * (input_count*(mixin_count+1))

    #Store Owned Input Wallets (Both owned and mixin)
    stealth_tx = []
    for i in range (0, len(xk_v)):
        stealth_tx = stealth_tx + [StealthTransaction.Generate(pub_viewkey, pub_spendkey, xk_v[i], xk_bf[i], r[r_index])]
        r_index = r_index + 1

    #Prompt Deposits
    print("Create Deposits:")
    for i in range(0, len(stealth_tx)):
        if (i < input_count):
            print("Input TX " + str(i) + ":\t[priv key: " + hex(stealth_tx[i].GetPrivKey(pri_viewkey, pri_spendkey)) + "]")
        else:
            print("Mixin TX " + str(i - input_count) + ":")
            
        print("Pub Key:\t" + print_point(CompressPoint(stealth_tx[i].pub_key)))
        print("DHE Point:\t" + print_point(CompressPoint(stealth_tx[i].dhe_point)))
        print("Value:\t\t" + str(xk_v[i] / (10**18)) + " ETH (" + str(xk_v[i]) + " wei)")
        print("BF:\t\t" + hex(xk_bf[i]))



        print()

    print("================================")

    #Create Output Addresses (sent to self via stealth address)
    stealth_tx_out = []
    bf_total = 0
    for i in range(0, outputs):
        if (i < (outputs-1)):
            v = xk_v_total // outputs
            bf = r[r_index]
            rand = r[r_index+1]
            r_index = r_index + 2
            
        else:
            v = (xk_v_total - (xk_v_total // outputs)*i)
            bf = (Ncurve-bf_total)
            rand = r[r_index]
            r_index = r_index + 1
            
        stealth_tx_out = stealth_tx_out + [StealthTransaction.Generate(pub_viewkey, pub_spendkey, v, bf, rand)]
        bf_total = (bf_total + bf) % Ncurve
            
        print("Output TX " + str(i) + ":")
        print("Pub Key:\t" + print_point(CompressPoint(stealth_tx_out[i].pub_key)))
        print("DHE Point:\t" + print_point(CompressPoint(stealth_tx_out[i].dhe_point)))
        print("Value:\t\t" + str(v / 10**18) + " ETH (" + str(v) + " wei)")
        print("BF:\t\t" + hex(bf))
        print()

    return stealth_tx_out

    #Store Mix In Transactions
    mixin_pubkeys = [multiply(G1, 0x108f37cb589b958b5c812da30f45de4cc5c9356f36a74c5827095b69f221beec),
                     multiply(G1, 0x1611eba0d164b81c6c5ad7dd071ad53ffe0e51438562f5e506d3a687d89f6abe),
                     multiply(G1, 0x141cb57b4f91bca66235ea114d8a79b9c52467cf416d9d71bb7d6c80844b89ff),
                     multiply(G1, 0x26a154b100b76a073aa9b94daccfc0d7a80e03934e2ce299c4234c30bb34fcc1)]

    mixin_cvalues = [multiply(G1, 0x0197f9643ab4fb7d6ce0ba1adf0f5a562c5a7f0bab01d6b5f09dfadc87fcc058),
                     multiply(G1, 0x1ae9a33e99ab07047c28086f2117fc461ed77aa467eead3ebe7b5689c046dd01),
                     multiply(G1, 0x0c11d1965f2b21332422d8f3f5f2ad20f51cea1c838bc9d710fdd849cb09e945),
                     multiply(G1, 0x01b5b4ebe7c6f5fcfe2928779e2a68d82309419c62fde433798c968e17f5d279)]

    mixin_tx = []
    for i in range(0, len(mixin_pubkeys)):
        mixin_tx = mixin_tx + [StealthTransaction(mixin_pubkeys[i], G1, mixin_cvalues[i], b"")] #dhe_point and encrypted data are not used (args 2 and 4)

    return stealth_tx
    
tx = RingCTTest_Repeatable()

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
        hasher.update(int_to_bytes32(output_count*2))
        for i in range(0, output_count):    
            hasher.update(int_to_bytes32(output_transactions[i].pub_key[0].n))
            hasher.update(int_to_bytes32(output_transactions[i].pub_key[1].n))

        subhashes = subhashes + [hasher.digest()]
        hasher = sha3.keccak_256()
        hasher.update(int_to_bytes32(output_count*2))
        for i in range(0, output_count):
            assert(eq(add(multiply(H, out_v[i]), multiply(G1, out_bf[i])),output_transactions[i].c_value)) 
            hasher.update(int_to_bytes32(output_transactions[i].c_value[0].n))
            hasher.update(int_to_bytes32(output_transactions[i].c_value[1].n))

        subhashes = subhashes + [hasher.digest()]
        hasher = sha3.keccak_256()
        hasher.update(int_to_bytes32(output_count*2))
        for i in range(0, output_count):
            hasher.update(int_to_bytes32(output_transactions[i].dhe_point[0].n))
            hasher.update(int_to_bytes32(output_transactions[i].dhe_point[1].n))

        subhashes = subhashes + [hasher.digest()]
        hasher = sha3.keccak_256()
        hasher.update(int_to_bytes32(output_count*3))
        for i in range(0, output_count):
            hasher.update(output_transactions[i].pc_encrypted_data.message)
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
        hasher.update(int_to_bytes32(output_count*2))
        for i in range(0, output_count):    
            hasher.update(int_to_bytes32(self.output_transactions[i].pub_key[0].n))
            hasher.update(int_to_bytes32(self.output_transactions[i].pub_key[1].n))

        subhashes = subhashes + [hasher.digest()]
        hasher = sha3.keccak_256()
        hasher.update(int_to_bytes32(output_count*2))
        for i in range(0, output_count):
            assert(eq(add(multiply(H, out_v[i]), multiply(G1, out_bf[i])),self.output_transactions[i].c_value)) 
            hasher.update(int_to_bytes32(self.output_transactions[i].c_value[0].n))
            hasher.update(int_to_bytes32(self.output_transactions[i].c_value[1].n))

        subhashes = subhashes + [hasher.digest()]
        hasher = sha3.keccak_256()
        hasher.update(int_to_bytes32(output_count*2))
        for i in range(0, output_count):
            hasher.update(int_to_bytes32(self.output_transactions[i].dhe_point[0].n))
            hasher.update(int_to_bytes32(self.output_transactions[i].dhe_point[1].n))

        subhashes = subhashes + [hasher.digest()]
        hasher = sha3.keccak_256()
        hasher.update(int_to_bytes32(output_count*3))
        for i in range(0, output_count):
            hasher.update(self.output_transactions[i].pc_encrypted_data.message)
            hasher.update(int_to_bytes32(bytes_to_int(self.output_transactions[i].pc_encrypted_data.iv)))

        subhashes = subhashes + [hasher.digest()]
        hasher = sha3.keccak_256()
        for i in range(0, len(subhashes)):
            print("Subhash (" + str(i) + "): " + hex(bytes_to_int(subhashes[i])))
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

        #Print encrypted data + iv
        print("[", end="")
        for i in range(0, output_count):
            print("\"" + hex(bytes_to_int(self.output_transactions[i].pc_encrypted_data.message[:32])) + "\",")
            print("\"" + hex(bytes_to_int(self.output_transactions[i].pc_encrypted_data.message[32:])) + "\",")
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
            print(hex(bytes_to_int(self.output_transactions[i].pc_encrypted_data.message[32:])) + ",")
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

def RingCTTest(input_count = 2, mixin_count = 3, outputs = 2, rngSeed=0):
    import random
    print()
    print("================================")
    print("Running RingCT Test (Repeatable)")
    print("input_count = " + str(input_count))
    print("mixin_count = " + str(mixin_count))
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
    if (rngSeed==0):
        random.seed()
    else:
        random.seed(rngSeed)
        
    for i in range(0, 100):
        r = r + [getRandomUnsafe()]

    #Store Committed Values (each 0.01 ETH)
    xk_v = [1 * (10**16)] * (input_count*(mixin_count+1))
    xk_v_total = (1 * (10**16)) * (input_count)
    xk_bf = [0] * len(xk_v)
    
    #for i in range(0, len(xk_v)):
    #	xk_bf = xk_bf + [r[r_index]]
    #	r_index = r_index + 1

    #Store Owned Input Wallets (Both owned and mixin)
    stealth_tx = []
    
    for i in range (0, len(xk_v)):
        stealth_tx = stealth_tx + [StealthTransaction.Generate(pub_viewkey, pub_spendkey, xk_v[i], xk_bf[i], r[r_index])]
        r_index = r_index + 1

    #Create Deposits (Both for input TX and mixin TX)
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
    import math
    stealth_tx_out = []
    stealth_tx_out_v = []
    stealth_tx_out_bf = []
    rp_out = []
    bf_total = 0
    bf_target = r[r_index]
    r_index = r_index+1
    
    for i in range(0, outputs):
        if (i < (outputs-1)):
            v = xk_v_total // outputs
            bf = r[r_index]
            rand = r[r_index+1]
            r_index = r_index + 2
            
        else:
            v = (xk_v_total - (xk_v_total // outputs)*i)
            bf = (Ncurve-bf_target-bf_total) % Ncurve
            rand = r[r_index]
            r_index = r_index + 1
            
        stealth_tx_out = stealth_tx_out + [StealthTransaction.Generate(pub_viewkey, pub_spendkey, v, bf, rand)]
        stealth_tx_out_v = stealth_tx_out_v + [v]
        stealth_tx_out_bf = stealth_tx_out_bf + [bf]
        bf_total = (bf_total + bf) % Ncurve
            
        print("Output TX " + str(i) + ":")
        print("Pub Key:\t" + print_point(CompressPoint(stealth_tx_out[i].pub_key)))
        print("DHE Point:\t" + print_point(CompressPoint(stealth_tx_out[i].dhe_point)))
        print("Value:\t\t" + str(v / 10**18) + " ETH (" + str(v) + " wei)")
        print("BF:\t\t" + hex(bf))
        print()

        #Create Pedersen Commitments
        pow10 = math.floor(math.log(v,10))
        val = v // 10**pow10
        rem = v - ( (val) * (10**pow10))
        bits = math.floor(math.log(val,4))+1
        
        #print("v: " + str(val) + ", pow10: " + str(pow10) + ", rem: " + str(rem))
        rp_out = rp_out + [PCRangeProof.Generate(val, pow10, rem, 2, bf)]
        
    #Retreive Private Keys for Input Transactions
    rct_xk = []
    for i in range(0, input_count):
        rct_xk = rct_xk + [stealth_tx[i].GetPrivKey(pri_viewkey, pri_spendkey)]

    rct_xk_v = xk_v[:input_count]
    rct_xk_bf = xk_bf[:input_count]
    rct_mixin_tx = stealth_tx[input_count:]

    #Print Input data for MyEtherWallet
    print()
    print("================================")
    print("MyEtherWallet Vectors")
    print("================================")
    print("Create Deposits (MEW):")
    print("value = " + str(xk_v_total))
    print("dest_pub_keys:")
    for i in range(0, len(stealth_tx)):
        if i > 0:
            print(",")
        print(print_point(CompressPoint(stealth_tx[i].pub_key)),end="")
    print("\n")

    print("dhe_points:")
    for i in range(0, len(stealth_tx)):
        if i > 0:
            print(",")
        print(print_point(CompressPoint(stealth_tx[i].dhe_point)),end="")
    print("\n")

    print("values:")
    for i in range(0, len(stealth_tx)):
        if i > 0:
            print(",")
        print(str(xk_v[i]),end="")
    print("\n")

    print("================================")
    print("Prove Ranges (MEW):")
    for i in range(0, len(rp_out)):
        rp_out[i].Print_MEW()
        print()

    print("================================")
    print("RingCT Send (MEW):")
    rct = RingCT.Sign(rct_xk, rct_xk_v, rct_xk_bf, rct_mixin_tx, stealth_tx_out, stealth_tx_out_v, stealth_tx_out_bf)
    rct.Print_MEW()

    print("================================")
    print("RingCT Withdraw (MEW):")
    return rct
   
tx = RingCTTest()

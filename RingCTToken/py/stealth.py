from ct import *

class StealthTransaction:
    pub_key = 0
    dhe_point = 0
    pc_encrypted_data = b""
    
    def __init__(self, pub_key, dhe_point, pc_encrypted_data):
        self.pub_key = pub_key
        self.dhe_point = dhe_point
        self.pc_encrypted_data = pc_encrypted_data

    def GenerateStealthTx(pubViewKey, pubSpendKey, value, blinding_factor):
        r = getRandom()
        R = multiply(G1, r)

        ss1 = hash_of_point(multiply(pubViewKey, r)) % Ncurve
        dest_pub_key = add(multiply(G1, ss1), pubSpendKey)

        ss2 = hash_of_point(multiply(pubSpendKey, r))
        encrypted_message = PCAESMessage.Encrypt(value, blinding_factor, ss2)

        return StealthTransaction(dest_pub_key, R, encrypted_message)

    def CheckOwnership(self, privViewKey, pubSpendKey):
        ss = hash_of_point(multiply(self.dhe_point, privViewKey)) % Ncurve
        pub_key = add(multiply(G1, ss), pubSpendKey)

        if (eq(self.pub_key, pub_key)):
            return True
        else:
            return False

    def GetPrivKey(self, privViewKey, privSpendKey):
        ss = hash_of_point(multiply(self.dhe_point, privViewKey)) % Ncurve
        
        priv_key = (ss + privSpendKey) % Ncurve
        return priv_key
        
    def DecryptData(self, privSpendKey):
        ss = hash_of_point(multiply(self.dhe_point, privSpendKey))
        return (self.pc_encrypted_data.Decrypt(ss))

    def Print(self):
        print("Stealth Transaction:")
        print("Public Key: " + print_point(CompressPoint(self.pub_key)))
        print("DHE Point: " + print_point(CompressPoint(self.dhe_point)))
        self.pc_encrypted_data.Print()

    def PrintScalars(self):
        s = self.pc_encrypted_data.to_scalars()
        for i in range(0, len(s)):
            print("s[" + str(i) + "]: " + hex(s[i]))
    
def StealthTxTest():
    MyPrivateViewKey = getRandom()
    MyPublicViewKey = multiply(G1, MyPrivateViewKey)
    
    MyPrivateSpendKey = getRandom()
    MyPublicSpendKey = multiply(G1, MyPrivateSpendKey)
    print("Generating Stealth Address: ")
    print("Public View Key: " + print_point(CompressPoint(MyPublicViewKey)))
    print("Public Spend Key: " + print_point(CompressPoint(MyPublicSpendKey)))


    print("\nGenerating ", end="")
    stx = StealthTransaction.GenerateStealthTx(MyPublicViewKey, MyPublicSpendKey, 5*(10**18), getRandom())
    stx.Print()

    print("\nChecking Ownership...", end="")
    if (stx.CheckOwnership(MyPrivateViewKey, MyPublicSpendKey)):
        print("Success!")
    else:
        print("Failure!")

    print("Private Key: " + hex(stx.GetPrivKey(MyPrivateViewKey, MyPrivateSpendKey)))

    (v, bf) = stx.DecryptData(MyPrivateSpendKey)
    print("Decrypted Value: " + str(v))
    print("Decrypted Blinding Factor: " + hex(bf))

    print("")
    stx.PrintScalars()

    print("\nFrom Scalars:")
    s = stx.pc_encrypted_data.to_scalars()
    pc = PCAESMessage.from_scalars(s)
    pc.Print()

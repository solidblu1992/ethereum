from OneBitRangeProof import *

if __name__ == "__main__":
    #Generate Proofs, 16 at a time
    commitments = []
    proofs = []

    for i in range(0, 1):
        c, proof = GenerateOneBitRangeProofs(count=64, asset_address=0)
        commitments += c
        proofs += [proof]

    #Sort commitments
    commitments = sorted(commitments)

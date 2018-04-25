from ring_signatures import *
from ct import *
from stealth import *
from ringct import *

def PrintTxExportAsDeposit(transaction_pool, stealth_addr=None):
    print("============================================")
    print("Deposit Multiple Data")
    print("============================================")
    #pub_keys
    print("Pub Keys:")
    #print("[", end = "")
    for i in range (0, len(transaction_pool)):
        print(hex(transaction_pool[i][0]), end = "")
        if (i < (len(transaction_pool)-1)):
            print(",")
        else:
            print("\n")

    #dhe_points
    print("DHE Points:")
    #print("[", end = "")
    for i in range (0, len(transaction_pool)):
        print(hex(transaction_pool[i][1]), end = "")
        if (i < (len(transaction_pool)-1)):
            print(",")
        else:
            print("\n")

    #values
    v_total = 0
    if (stealth_addr != None):
        print("Values:")
        #print("[", end = "")
        for i in range (0, len(transaction_pool)):
            stealth_tx = StealthTransaction(ExpandPoint(transaction_pool[i][0]), #pub_key compressed
                                            ExpandPoint(transaction_pool[i][1]), #dhe_point compressed
                                            ExpandPoint(transaction_pool[i][2]), #c_value compressed
                                            PCAESMessage(int_to_bytes64(transaction_pool[i][3]),  #pc_encrypted_data.message
                                                         int_to_bytes16(transaction_pool[i][4]))) #pc_encrypted_data.iv

            data = stealth_tx.DecryptData(stealth_addr[1])
            print(str(data[0]), end = "")
            v_total = v_total + int(data[0])
            
            if (i < (len(transaction_pool)-1)):
                print(",")
            else:
                print("\n")

        print("Total Value = " + str(v_total) + " wei or " + str(v_total / 10**18) + " ETH")
        print()
    else:
        print("C Values:")
        #print("[", end = "")
        for i in range (0, len(transaction_pool)):
            print(hex(transaction_pool[i][2]), end = "")
            
            if (i < (len(transaction_pool)-1)):
                print(",")
            else:
                print("\n")

    print()


StealthAddressExport = [0x19e857368117ca5aee6734b101b1773052ae24d54f654e41e1e586dbfd77800b, 0x1c097a5cd668c0bf408d7e05ad11887dd91a2553b821aec9c5809e19097c785f]

UTXOPoolExport = [[0x2ed370bf290af178cdccbf58d64426b13442eb0a2f3b90a60b6dcb1192d273ce,
 0x1fbb43ae4a98d45cd20a3f71746a009b50b4a9d90bb4ace8c57a505ae076182a,
 0x1dce3fd5c51121f5e399d16c7439951f2de0883fa06edea393e9aad512ab6a25,
 0xbdf64b5eb3dca38a94a33725c1af82d54e5c301b78b4fbc55d0c664ae1e0a5f9c0d1cb011db83a3bff6a8e80d4bf5fe488901b05c92f81975cebcb4b434429e7,
 0xd0dbfd515e8faaeafa02ae1e19c97de],
[0xa4934dd2a5d9f805956f568840c342640dfe0a4b7606de56b9715a49f7d22490,
 0x2877a588cefd79efe381e0129d6743eab4660b25fff00b5921be8fc1c3a2ebd9,
 0x1dce3fd5c51121f5e399d16c7439951f2de0883fa06edea393e9aad512ab6a25,
 0x9b1737fefd93e419f5f05342ba6eda371b3d5dd957ad3174ccfb7d54cf210ee19d81fbd542f09e1a4c8cb42eba713ea9cb7c9f54398ca1e50d354dd3a3a050c9,
 0x7dfd335777b6a03a13b1076287c275b2],
[0x9fefa3bc6ba9da59ab1343c4e8bdbbfc73ca89ec8eb7d4300c43a38d939aab40,
 0xaea1286d32cea80dd615f1351546bdc65c4a8e7d9736d23ae1537d19d13252b0,
 0x150143471f56dcae9660a0d11cec311f0cdb05e8cf97668e94839d1484e54810,
 0xb080d87d6f5c3a46c015bb875303fe8aeb5f520b6eb5541900b67ce3f217fe794eb3161411e93d694dbb7d53b5801b9cefa36c99fda7af445a473dfd87879cae,
 0x443fa665bc8a87b211caa4cd50257b40],
[0x25b44febc079390a914a549dfe8849c7431b538b72b887f87d95bdd05656b234,
 0x7274b7c978345f15833d480380b155d69e5e5b4b8d968a45a0030b81c7c9427,
 0xad22152243b24624aa87e22899c4235829079e5f2a7772c1449a77ce04a929b3,
 0xeded80683fb187baa5870162407d085709a2df1e9eb6090835421b92b7f54c4f30570efc0ec58045a85881559af0141f58439a5a531a9a0f9b27af3a69ede1e2,
 0xe0f62699de151773b9fc784d17809d95],
[0x25e62b142e1c6fed16e95b474edef4af48d6ebc57c08ffdb93f86462a9ea3a14,
 0x8381f196af521809d211a3703301fb2aff3268aceaf7fa5ed2155ddb29d231a,
 0x1de8dc2c64841908f11b290fb64a010c00f6d3aa1fe9d79037b6c7c13ba1e66b,
 0x463113d73fa4e329651d53ed40fd71d27a02cdf0a0fff840be7038d9cba102121f7c25451616375cac6298e48e3f754bb51e6f845e95e280cd9f786de131a8b4,
 0x69cda6b3e611e482703b7871b47815fb],
[0xa5c35483471cd8103d95ce57c00d6ff27a290544b2702544f1937741d7606a01,
 0xa1028dc5099cad435861d253dcc466575b141960d56aa6e783c07e41fbbd6ca5,
 0x1dce3fd5c51121f5e399d16c7439951f2de0883fa06edea393e9aad512ab6a25,
 0x4b5f60422fdbd7dc6b96080daadd19e1fba5c63d9824317138add3998771c169c2e22eb2cc036e39c0c2da53118562e38e04eb26ed4de46e6f8d7c6f87c9c06f,
 0xaaad1d0707fc93b9ec8018aa7450d4b4],
[0xa1eeb790353ade0cc726b926561da507b16beb50e3f58bbcde87baa1f7ad492a,
 0xa3b071ebbec827ed9c9ca6f3ff3390eab7063adb8d9113030aa61fef617ebc8,
 0x1dce3fd5c51121f5e399d16c7439951f2de0883fa06edea393e9aad512ab6a25,
 0x1c2fed83f36623cee8cb8cb0cab705a355d969e1ecaebdbd11ad74fb15de317403b679486f9b9709f975ad286e4696c58835c5d870389574a02b980f319618b0,
 0xed6e18b6e913667855dae516cdc41a1f],
[0xa3c243b27a8e6480b5031f54e857496391c5c57c692cac44110a48debf692e7a,
 0x8897b92ef6e1aa974140b554bbaf9e9ee3bdb25f600986e9c7137fc912739b9a,
 0x150143471f56dcae9660a0d11cec311f0cdb05e8cf97668e94839d1484e54810,
 0xe8b46eaf97f2c2870f323572203b1a9b81b223a0a6fd9aa5a66b454459d4ff165af220e5456f7f9a80cc1306a1a516b95059a8f57a5fc2d6d4bc6cba69d87a14,
 0x6e5cf4e91469a1f9dfe82ec91dd52cf9]]

MixinPoolExport = []

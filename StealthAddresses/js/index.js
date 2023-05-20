const curve = require('noble-secp256k1');
const bufToBigInt = require('bigint-conversion').bufToBigint;
const { keccak256 } = require("ethereum-cryptography/keccak.js");

//Helper Function
function eth_addr_from_pubkey(Y) {
    return keccak256(Y.toRawBytes(false)).buffer.slice(0,20);
}

//Main Code Block
class StealthTx {
    constructor (R = null, addr = null, x = null) {
        this.R = R;
        this.addr = addr;
        this.x = x;
    }

    print() {
        console.log("Stealth Tx:");
        console.log("\tAddress: 0x" + bufToBigInt(this.addr).toString(16));
        console.log("\tDHE Point: 0x" + this.R.toHex(true));
        if (this.x == null) {
            console.log("\tPrivate Key: unknown");
        }
        else {
            console.log("\tPrivate Key: known");
        }
    }
}

class StealthAddress {
    constructor(Yv = null, Ys = null, xv = null, xs = null) {
        this.Yv = Yv;
        this.Ys = Ys;
        this.xv = xv;
        this.xs = xs;
    }

    //Create Stealth Address from Private Keys, or generate new Private Keys
    static fromPrivKeys(xs = null, xv = null) {
        if (xs == null || xv == null) {
            xv = bufToBigInt(curve.utils.randomPrivateKey());
            xs = bufToBigInt(curve.utils.randomPrivateKey());
        }
        var Yv = curve.Point.BASE.multiply(xv);
        var Ys = curve.Point.BASE.multiply(xs);
        return new StealthAddress(Yv, Ys, xv, xs);
    }

    //Create Stealth Address from Public Keys
    static fromPubKeys(Ys, Yv) {
        return new StealthAddress(Yv, Ys, null, null);
    }

    //Create a Public version of Stealth Address Object (stripping out private keys)
    asPublic() {
        return new StealthAddress(this.Yv, this.Ys, null, null);
    }

    async generateTx() {
        var r = bufToBigInt(curve.utils.randomPrivateKey());
        var R = curve.Point.BASE.multiply(r);
        var shared_secret = await curve.utils.sha256(this.Yv.multiply(r).toRawBytes(false));
        shared_secret = bufToBigInt(shared_secret);
        var Y = curve.Point.BASE.multiply(shared_secret).add(this.Ys);
        var addr = eth_addr_from_pubkey(Y);
        return new StealthTx(R, addr);
    }

    async recoverTx(tx) {
        var shared_secret = await curve.utils.sha256(tx.R.multiply(this.xv).toRawBytes(false));
        shared_secret = bufToBigInt(shared_secret);
        var Y = curve.Point.BASE.multiply(shared_secret).add(this.Ys);
        var addr = eth_addr_from_pubkey(Y);
        if (bufToBigInt(addr) != bufToBigInt(tx.addr)) { return false; }
        tx.x = (shared_secret + this.xs) % curve.CURVE.n;
        return true;
    }

    print() {
        console.log("Stealth Address: 0x" + this.Yv.toHex(true) + this.Ys.toHex(true));
        if (this.xv == null) {
            console.log("\tPrivate View Key: unknown");
        }
        else {
            console.log("\tPrivate View: known");
        }
        if (this.xs == null) {
            console.log("\tPrivate Spend Key: unknown");
        }
        else {
            console.log("\tPrivate Spend: known");
        }
    }
}

async function test_module() {
    //Generate Stealth Address
    var stealth_address = StealthAddress.fromPrivKeys();
    stealth_address.print();

    //Generate Stealth Tx
    var pub_stealth_address = stealth_address.asPublic();
    pub_stealth_address.print();
    var tx = await pub_stealth_address.generateTx();
    tx.print();

    //Recover Tx Private Key using stealth address
    var success = await stealth_address.recoverTx(tx);
    if (success) {
        console.log("recoverTx success");
    }
    else {
        console.log("recoverTx failed or not for this stealth address");
    }
}

test_module();

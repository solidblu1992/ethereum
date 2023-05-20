const curve = require('noble-secp256k1');
const bufToBigInt = require('bigint-conversion').bufToBigint;
const { keccak256 } = require("ethereum-cryptography/keccak.js");

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

    async generateTx() {
        var r = bufToBigInt(curve.utils.randomPrivateKey());
        var R = curve.Point.BASE.multiply(r);
        var shared_secret = await curve.utils.sha256(this.Yv.multiply(r).toRawBytes(false));
        shared_secret = bufToBigInt(shared_secret);
        var Y = curve.Point.BASE.multiply(shared_secret).add(this.Ys);
        var addr = keccak256(Y.toRawBytes(false)).buffer.slice(0,20);
        return new StealthTx(R, addr);
    }

    async recoverTx(tx) {
        var shared_secret = await curve.utils.sha256(tx.R.multiply(this.xv).toRawBytes(false));
        shared_secret = bufToBigInt(shared_secret);
        var Y = curve.Point.BASE.multiply(shared_secret).add(this.Ys);
        var addr = keccak256(Y.toRawBytes(false)).buffer.slice(0,20);
        if (bufToBigInt(addr) != bufToBigInt(tx.addr)) { return false; }
        tx.x = (shared_secret + this.xs) % curve.CURVE.n;
        return true;
    }

    print() {
        console.log("Stealth Address: 0x" + this.Yv.toHex(true) + this.Ys.toHex(true));
    }
}
async function generate_stealth_address() {
    //Generate Stealth Address
    var stealth_address = StealthAddress.fromPrivKeys();
    stealth_address.print();

    //Generate Stealth Tx
    var tx = await stealth_address.generateTx();
    tx.print();

    if (stealth_address.recoverTx(tx)) {
        console.log("recoverTx success");
    }
    else {
        console.log("recoverTx failed or not for this stealth address");
    }
    tx.print();
}

generate_stealth_address();

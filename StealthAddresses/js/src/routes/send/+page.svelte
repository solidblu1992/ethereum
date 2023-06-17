<script lang="ts">
	import { keccak256 } from "ethereum-cryptography/keccak";
    import { bufToBigint, bigintToBuf, hexToBigint, bigintToHex } from "bigint-conversion";
	import { secp256k1 } from "ethereum-cryptography/secp256k1";
	const Fp = secp256k1.CURVE.Fp;
	import { Point } from "noble-secp256k1";
	import { cnBase58 } from "@xmr-core/xmr-b58";
    import { FetchRequest, assert, ethers } from "ethers";

	let inp_stealth_address = "45qrwW7fP399QLhQepsC3ShpDQNPCy3yjWjAMfq7aYSHgUJosaKVEPRea8aDzgVX7NCunWUFoHhik3a2KDLxhgrjQCw2yLp";

	let stealth_address_checksum_fail = false;

	let pub_spend_key = "";
	let pub_view_key = "";
	let tx_address = "";
	let dhe_point = "";

	function generate_stealth_tx() {
		//Decode Stealth Address and Verify Checksum
		stealth_address_checksum_fail = false;
		if (!validate_stealth_address(inp_stealth_address)) {
			stealth_address_checksum_fail = true;
			return;
		}

		//Pick random DHE point
		let r = bufToBigint(secp256k1.utils.randomPrivateKey());
		dhe_point = "0x" + Point.BASE.multiply(r).toHex(true);

		//Calculate Shared Secret
		let Yv = expand_pub_key(hexToBigint((pub_view_key.slice(2))));
		let buffer = Yv.multiply(r).toRawBytes(false);
		let ss = bufToBigint(keccak256(buffer)) % secp256k1.CURVE.n;
		
		//Calculate New Public Key
		let Ys = expand_pub_key(hexToBigint((pub_spend_key.slice(2))));
		let Ynew = Point.BASE.multiply(ss).add(Ys);

		//Calculate Ethereum Address
		tx_address = ethers.getAddress(ethers.keccak256(Ynew.toRawBytes(false)).slice(2, 42));
	}

	function validate_stealth_address(stealth_address: string): boolean {
		let stealth_address_decoded = cnBase58.decode(stealth_address);
		let buffer = new Uint8Array(bigintToBuf(hexToBigint(stealth_address_decoded), true));
		
		//Unpack Stealth Address
		let prefix = buffer.at(0) ?? 0;
		let Ys_bytes = new Uint8Array(33);
		Ys_bytes.set([0x02]); //Assume Positive Point
		Ys_bytes.set(buffer.slice(1, 33), 1);
		let Yv_bytes = new Uint8Array(33);
		Yv_bytes.set([0x02]); //Assume Positive Point
		Yv_bytes.set(buffer.slice(33, 65), 1);
		let checksum = buffer.slice(65);

		//Check checksum
		stealth_address_checksum_fail = false;
		let checksum_buffer = new Uint8Array(65);
		checksum_buffer.set([prefix]);
		checksum_buffer.set(Ys_bytes.slice(1), 1);
		checksum_buffer.set(Yv_bytes.slice(1), 33);
		let checksum_verify = keccak256(checksum_buffer).slice(0, 4);
		if (bufToBigint(checksum) != bufToBigint(checksum_verify)) {
			pub_spend_key = "";
			pub_view_key = "";
			return false;
		}
		
		pub_spend_key = "0x" + bufToBigint(Ys_bytes).toString(16);
		pub_view_key = "0x" + bufToBigint(Yv_bytes).toString(16);
		return true;
	}

	function expand_pub_key(compressed_pub_key: bigint): Point {
		let pub_key_buffer = new Uint8Array(bigintToBuf(compressed_pub_key, true));
		let sign = pub_key_buffer.at(0) ?? 0;

		//Invalid Public Key, malformated!
		if (sign < 2 || sign > 3) {
			return Point.ZERO;
		}
		sign = sign - 2;

		let x = bufToBigint(pub_key_buffer.slice(1));

		//Calculate Y cordinates
		//y^2 = x^3 + a*x + b
		let y2 = Fp.add(Fp.pow(x, BigInt(3)), secp256k1.CURVE.b);
		let y = Fp.sqrt(y2);

		//Invalid Public Key, not on curve!
		if (Fp.pow(y, BigInt(2)) != y2) {
			return Point.ZERO;
		}

		//Check Sign
		let current_sign = y % BigInt(2);
		if (current_sign != BigInt(sign)) {
			y = secp256k1.CURVE.p - y;
		}
		
		return new Point(x, y);
	}
</script>

<div class="horizontal-center">
	<h3>Send a Stealth Transaction</h3>
	<h2>Use this tool to send a transaction to a Stealth Address</h2>
	<br>
	<table>
		<tr>
			<th>Stealth Address:</th>
			<td><input bind:value={inp_stealth_address} style="min-width:1000px;"/></td>
		</tr>
	</table>
	<button on:click={generate_stealth_tx} aria-label="Generate Stealth Transaction">
		Generate Stealth Transaction
	</button>
	{#if stealth_address_checksum_fail}
		<div style="color:Red;">Invalid Stealth Address: Checksum Invalid</div>
	{/if}
	{#if pub_spend_key != ""}
	<table>
		<tr>
			<th>Public Spend Key:</th>
			<td>{pub_spend_key}</td>
		</tr>
		<tr>
			<th>Public View Key:</th>
			<td>{pub_view_key}</td>
		</tr>
		<br>
		<tr>
			<th>Stealth Tx Address:</th>
			<td>{tx_address}</td>
		</tr>
		<tr>
			<th>DHE Point:</th>
			<td>{dhe_point}</td>
		</tr>
	</table>
	{/if}
</div>

<style>
	th {
		text-align: left;
		white-space: nowrap;
	}
	.horizontal-center {
		width: 100%;
		height: 100%;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: top;
		gap: 1rem;
		flex: 1;
	}
</style>

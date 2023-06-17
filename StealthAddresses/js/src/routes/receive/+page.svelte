<script lang="ts">
	import { keccak256 } from "ethereum-cryptography/keccak";
    import { bufToBigint, bigintToBuf, hexToBigint, bigintToHex } from "bigint-conversion";
	import { secp256k1 } from "ethereum-cryptography/secp256k1";
	const Fp = secp256k1.CURVE.Fp;
	import { Point } from "noble-secp256k1";
	import { cnBase58 } from "@xmr-core/xmr-b58";
    import { FetchRequest, assert, ethers } from "ethers";

	let files: FileList;
	let inp_password = "";
	let inp_tx_address = "0x57dc2da534eE7B35c354d9d11938aa7DEb792858";
	let inp_dhe_point = "0x035cc213126d7c7eac19334c09e6bc0363b6344afff140619b323dd4b8888887ad";

	function check_tx_ownership() {
		//Load Keystore
		let t = files[0].stream();
	}
</script>

<div class="horizontal-center">
	<h3>Receive a Stealth Transaction</h3>
	<h2>Use this tool to receive a transaction for Stealth Address</h2>
	<br>
	<table>
		<tr>
			<th>Stealth Tx Address:</th>
			<td><input bind:value={inp_tx_address} style="min-width:620px;"/></td>
		</tr>
		<tr>
			<th>DHE Point:</th>
			<td><input bind:value={inp_dhe_point} style="min-width:620px;"/></td>
		</tr>
		<tr>
			<th>Keystore File:</th>
			<td><input accept="text/json" bind:files type="file"/></td>
		</tr>
		<tr>
			<th>Password:</th>
			<td><input bind:value={inp_password} type="password"/></td>
		</tr>
	</table>
	<button on:click={check_tx_ownership} aria-label="Check to see if a transaction was for us">
		Check Tx Ownership
	</button>
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

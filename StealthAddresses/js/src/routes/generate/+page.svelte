<script lang="ts">
	import { keccak256 } from "ethereum-cryptography/keccak";
    import { bufToBigint } from "bigint-conversion";
	import { secp256k1 } from "ethereum-cryptography/secp256k1";
	import { Point } from "noble-secp256k1";
	import { cnBase58 } from "@xmr-core/xmr-b58";
	import { ethers } from "ethers";
	
	//Generation Variables
	let stealth_address = "";
	let pub_spend_key = "";
	let pub_view_key = "";
	let keystore_json = "";

	//Password Variables
	let inp_password = "";
	let inp_password_confirm = "";
	let password_blank_error = false;
	let password_mismatch_error = false;

	function generate_stealth_address() {
		//Check password
		password_blank_error = false;
		password_mismatch_error = false;
		if (inp_password != inp_password_confirm) {
			password_mismatch_error = true;
			return;
		}
		if (inp_password.length == 0) {
			password_blank_error = true;
			return;
		}

		//Generate new private view and spend keys for secp256k1
		let priv_spend_key = bufToBigint(secp256k1.utils.randomPrivateKey());
		let priv_view_key = bufToBigint(secp256k1.utils.randomPrivateKey());
		let Ys = Point.BASE.multiply(priv_spend_key);
		let Yv = Point.BASE.multiply(priv_view_key);
		
		//Only allow points that compress to the 0x02 sign (positive) so that they fit in a Monero Address
		//If negative then negate key for positive point
		let raw_bytes = Ys.toRawBytes(true);
		if (raw_bytes.at(0) != 0x02) {
			priv_spend_key = (secp256k1.CURVE.n - priv_spend_key);
			Ys.y = (secp256k1.CURVE.p - Ys.y);
		}
		raw_bytes = Yv.toRawBytes(true);
		if (raw_bytes.at(0) != 0x02) {
			priv_view_key = (secp256k1.CURVE.n - priv_view_key);
			Yv.y = (secp256k1.CURVE.p - Yv.y);
		}
		stealth_address = pubkeys_to_stealth_address(Ys, Yv);

		//Store private keys in encrypted wallet
		let spend_key_json = new ethers.Wallet(priv_spend_key.toString(16)).encryptSync(inp_password);
		let view_key_json = new ethers.Wallet(priv_view_key.toString(16)).encryptSync(inp_password);

		let new_keystore_json = {
			"address:": stealth_address,
			"spend_key": spend_key_json,
			"view_key": view_key_json
		};
		keystore_json = JSON.stringify(new_keystore_json);

		//Update UI
		pub_spend_key = "0x" + Ys.toHex(true);
		pub_view_key = "0x" + Yv.toHex(true);
		inp_password = "";
		inp_password_confirm = "";
	}

	function pubkeys_to_stealth_address(Ys: Point, Yv: Point): string {
		let prefix = new Uint8Array([18]);
		let Ys_bytes = Ys.toRawBytes(true).slice(1); //Only positive points
		let Yv_bytes = Yv.toRawBytes(true).slice(1); //Only positive points
		let suffix = new Uint8Array(4);

		let checksum_buffer = new Uint8Array(1 + Ys_bytes.length*2);
		checksum_buffer.set(prefix);
		checksum_buffer.set(Ys_bytes, 1);
		checksum_buffer.set(Yv_bytes, 1 + Ys_bytes.length);

		let checksum = keccak256(checksum_buffer).slice(0, 4);
		
		let buffer = new Uint8Array(checksum_buffer.length + checksum.length);
		buffer.set(checksum_buffer);
		buffer.set(checksum, checksum_buffer.length);		

		return cnBase58.encode(bufToBigint(buffer).toString(16));
	}

	function download_keystore() {
		json_to_file(keystore_json, "keystore.json");
	}

	// Function to download data to a file
	function json_to_file(data: string, filename: string) {
		var file = new Blob([data], {type: "JSON"});
		var a = document.createElement("a"),
				url = URL.createObjectURL(file);
		a.href = url;
		a.download = filename;
		document.body.appendChild(a);
		a.click();
		setTimeout(function() {
			document.body.removeChild(a);
			window.URL.revokeObjectURL(url);  
		}, 0);
	}
</script>

<div class="horizontal-center">
	<h3>Generate New Stealth Address</h3>
	<h2>Use this tool to generate a new Stealth Address keystore</h2>
	<br>
	<table>
		<tr>
			<th>Password:</th>
			<td><input bind:value={inp_password} type="password"/></td>
		</tr>
		<tr>
			<th>Confirm Password:</th>
			<td><input bind:value={inp_password_confirm} type="password"/></td>
		</tr>
	</table>	
	{#if password_blank_error}
		<div style="color:Red;">Password is blank!</div>
	{/if}
	{#if password_mismatch_error}
		<div style="color:Red;">Passwords do not match!</div>
	{/if}
	<button on:click={generate_stealth_address} aria-label="Generate a new stealth address">
		Generate Stealth Address
	</button>
	{#if stealth_address != ""}
		<table>
			<tr>
				<th>Stealth Address:</th>
				<td>{stealth_address}</td>
			</tr>
			<tr>
				<th>Public Spend Key:</th>
				<td>{pub_spend_key}</td>
			</tr>
			<tr>
				<th>Public View Key:</th>
				<td>{pub_view_key}</td>
			</tr>
		</table>
		<button on:click={download_keystore} aria-label="Download private spend/view keys in .json format">
			Download Generated Keystore
		</button>
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

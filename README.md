# authenticode-sign

[![NPM Version](https://img.shields.io/npm/v/authenticode-sign)](https://www.npmjs.com/package/authenticode-sign)
![NPM Type Definitions](https://img.shields.io/npm/types/authenticode-sign)
[![Build Status](https://ci.systest.eu/api/badges/gergof/authenticode-sign/status.svg)](https://ci.systest.eu/gergof/authenticode-sign)
[![GitHub License](https://img.shields.io/github/license/gergof/authenticode-sign)](https://github.com/gergof/authenticode-sign/blob/master/LICENSE)

NodeJS cross-platform module to code-sign windows executables with Authenticode signatures.

### What is it?

`authenticode-sign` is a simple NodeJS module written in TypeScript that can be used to create authenticode signature for Windows Portable Executable files (.exe). It can be used to programatically sign code with your own crypto tools. As far as my testing goes, this one is the only pure javascript module that creates working authenticode signatures and can use your own signing tools.

I took a lot of inspiration from the [Jsign](https://github.com/ebourg/jsign), [osslsigncode](https://github.com/mtrojnar/osslsigncode) and [resedit](https://github.com/jet2jet/resedit-js) projects.

The library currently only supports PE files (EXE, SYS, DLL, etc), but in the future I would like to extend it for MSI, CAB and CAT files as well.

### How to use it?

The library is bundled as an [ES Module](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Modules). After installing it with `npm install authenticode-sign` you have to create a `SignerObject` which will handle the actual crypto operations (hashing, signing and sending the timestamping request).

The `SignerObject` has to implement this interface:
```ts
interface SignerObject {
	getDigestAlgorithmOid: () => OID;
	getSignatureAlgorithmOid: () => OID;
	getCertificate: () => Buffer;
	digest: DigestFn;
	sign: SignFn;
	timestamp?: TimestampFn;
}
```

Where:
- `getDigestAlgorithmOid()` returns the Object ID of the digest algorithm. For example `2.16.840.1.101.3.4.2.1` for SHA256. You can get the list of hash algorithm OIDs from [oidref hashAlgs](https://oidref.com/2.16.840.1.101.3.4.2)
- `getSignatureAlgorithmOid()` return the Object ID of the signature algorithm. For example `1.2.840.10045.4.3.2` for SHA256Ecdsa. For these you don't have a nice list like the one for the hashing algorithms, but you can still use [oidref.com](https://oidref.com) to find the required OIDs
- `getCertificate()` returns the X.509 certificate in a DER encoded (binary) format as a NodeJS buffer
- `digest(data: Iterator<Buffer>)` hashes the supplied data and returns it as a buffer (can be async)
- `sign(data: Iterator<Buffer>)` signes the supplied data and returns it as a buffer (can be async)
- `timestamp(data: Buffer)` sends the timestamp request to your TSA and returns the response as a buffer (can be async). This method is optional, if you don't implement it, the signature will not be timestamped.

### Example usage

You can see the whole example (including test files) in the test directory.

```ts
import fsp from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { AuthenticodeSigner, PEFile } from 'authenticode-sign';

// we will use nodeJS's crypto module for the crypto operations
// but you can use any crypto engine that supports hashing and signing
import crypto from 'crypto';

const main = async () => {
	// create work directory
	const dir = path.dirname(fileURLToPath(import.meta.url));
	const workdir = path.join(dir, 'work')
	await fsp.mkdir(path.join(dir, 'work'), {recursive: true});

	// read the EXE file to a Buffer
	const file = await fsp.readFile(path.join(dir, 'test.exe'));

	// create the PEFile that will be signed using that buffer
	const exe = new PEFile(file);

	// you can output the checksum if you would like
	console.log('Checksum:', exe.calculateChecksum().toString(16));

	// read the certificate already encoded in DER format
	const certDer = await fsp.readFile(path.join(dir, 'signer.cer'))

	// read the private key encoded in PEM format
	const key = (await fsp.readFile(path.join(dir, 'signer.key'))).toString('utf8')

	// create the AuthenticodeSigner
	const signer = new AuthenticodeSigner({
		getDigestAlgorithmOid: () => '2.16.840.1.101.3.4.2.1', // return OID for sha256
		getSignatureAlgorithmOid: () => '1.2.840.10045.4.3.2', // return OID for ecdsa with sha256
		getCertificate: () => certDer, // return the binary certificate
		digest: async (dataIterator) => {
			// create a SHA256 hash using NodeJS Crypto module
			const hash = crypto.createHash('sha256')

			// consume the whole iterator
			while (true) {
				const it = dataIterator.next();
				if(it.done){
					break;
				}

				// update the hash with the current value
				await hash.update(it.value)
			}

			// return the digest in binary format as a buffer
			return hash.digest()
		},
		sign: async (dataIterator) => {
			// create a signature using SHA256 digest
			const signature = crypto.createSign('sha256')

			// consume the whole iterator
			while (true) {
				const it = dataIterator.next();
				if(it.done) {
					break;
				}

				// update the signature with the current value
				await signature.update(it.value)
			}

			// sign it with your private key and return it as a buffer
			return signature.sign(key)
		},
		timestamp: async data => {
			// send the timestamp request to one of the public timestamping servers
			// see the list of free TSAs: https://gist.github.com/Manouchehri/fd754e402d98430243455713efada710
			const resp = await fetch('http://timestamp.digicert.com', {
				method: 'POST',
				headers: {
					'Content-type': 'application/timestamp-query',
					'Content-length': data.byteLength.toString()
				},
				body: data
			});

			return Buffer.from(await resp.arrayBuffer());
		}
	})

	// do the actual signing of the executable
	// this method will return the signed executable as a buffer
	const result = await signer.sign(exe);

	console.log('Saving result file...')

	// save the signed file
	await fsp.writeFile(path.join(workdir, 'test.signed.exe'), result);

	console.log('Done')
}

main();
```

### Testing the library

You can use `npm test` and it will sign an empty EXE with a pregenerated ECDSA256 key and SHA256 hashing algorithm. The result is saved to `test/work/test.signed.exe`. To verify the signature it's the easiest to use Windows's built in signature verification tool (right click -> properties -> digital signatures), but the next best thing is to use the `osslsigncode verify -CAfile test/ca.crt -verbose test/work/test.signed.exe` command.

### Managed code signing

If you would like to sign your executables for Windows from any OS you can check out my other open source project: [Signo](https://github.com/gergof/signo). It's still in a development stage, but that tool can be used to sign executables using any PKCS#11 hardware (or software) token from anywhere, which is pretty useful, since all newly created codesigning certificates have to be stored on a HSM. With Signo and a cheap Yubikey FIPS token you can get some benefits of a networked HSM while not breaking the bank.

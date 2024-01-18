/* eslint-disable no-console */
import fsp from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { AuthenticodeSigner, PEFile } from '../src/index.js';
import crypto from 'crypto';
import fetch from 'node-fetch';

const main = async () => {
	const dir = path.dirname(fileURLToPath(import.meta.url));
	const workdir = path.join(dir, 'work');
	await fsp.mkdir(path.join(dir, 'work'), { recursive: true });

	const file = await fsp.readFile(path.join(dir, 'test.exe'));

	const exe = new PEFile(file);
	console.log('Checksum:', exe.calculateChecksum().toString(16));

	const certDer = await fsp.readFile(path.join(dir, 'signer.cer'));
	const key = (await fsp.readFile(path.join(dir, 'signer.key'))).toString(
		'utf8'
	);
	const signer = new AuthenticodeSigner({
		getDigestAlgorithmOid: () => '2.16.840.1.101.3.4.2.1', // sha256
		getSignatureAlgorithmOid: () => '1.2.840.10045.4.3.2', // ecdsa with sha256
		getCertificate: () => certDer,
		digest: async dataIterator => {
			const hash = crypto.createHash('sha256');

			while (true) {
				const it = dataIterator.next();
				if (it.done) {
					break;
				}

				await hash.update(it.value);
			}

			return hash.digest();
		},
		sign: async dataIterator => {
			const signature = crypto.createSign('sha256');

			while (true) {
				const it = dataIterator.next();
				if (it.done) {
					break;
				}

				await signature.update(it.value);
			}

			return signature.sign(key);
		},
		timestamp: async data => {
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
	});

	const result = await signer.sign(exe);

	console.log('Saving result file...');

	await fsp.writeFile(path.join(workdir, 'test.signed.exe'), result);

	console.log('Done');
};

main();

import { OID } from './types.js';

export type DigestFn = (data: Iterator<Buffer>) => Promise<Buffer>;
export type SignFn = (data: Iterator<Buffer>) => Promise<Buffer>;
export type TimestampFn = (data: Buffer) => Promise<Buffer>;

interface SignerObject {
	getDigestAlgorithmOid: () => OID;
	getSignatureAlgorithmOid: () => OID;
	getCertificate: () => Buffer;
	getIntermediateCertificates?: () => Buffer[];
	digest: DigestFn;
	sign: SignFn;
	timestamp?: TimestampFn;
}

export default SignerObject;

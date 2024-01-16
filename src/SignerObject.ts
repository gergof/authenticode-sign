import { OID } from './types.js';

export type DigestFn = (data: Iterator<Buffer>) => Promise<Buffer>;
export type SignFn = (data: Iterator<Buffer>) => Promise<Buffer>;
export type TimestampFn = (data: Iterator<Buffer>) => Promise<Buffer>;

interface SignerObject {
	getDigestAlgorithmOid: () => OID;
	getSignatureAlgorithmOid: () => OID;
	getCertificate: () => Buffer;
	digest: DigestFn;
	sign: SignFn;
	timestamp: TimestampFn;
}

export default SignerObject;

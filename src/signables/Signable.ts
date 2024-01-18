import pkijs from 'pkijs';

import { DigestFn } from '../SignerObject.js';
import SpcIndirectDataContent from '../asn1/SpcIndirectDataContent.js';

abstract class Signable {
	public abstract getIndirectData(
		digest: DigestFn,
		digestAlgorithm: pkijs.AlgorithmIdentifier
	): Promise<SpcIndirectDataContent>;
	public abstract getSignature(): Buffer;
	public abstract setSignature(signedData: Buffer): void;
	public abstract getFile(): Buffer;
}

export default Signable;

import asn1 from 'asn1js';
import pkijs from 'pkijs';

import SignOptions from './SignOptions.js';
import SignerObject from './SignerObject.js';
import {
	OID_CONTENT_TYPE,
	OID_MESSAGE_DIGEST,
	OID_SIGNED_DATA,
	OID_SIGNING_TIME,
	OID_SPC_INDIRECT_DATA,
	OID_SPC_INDIVIDUAL_SP_KEY_PURPOSE,
	OID_SPC_STATEMENT_TYPE
} from './asn1/OIDs.js';
import Signable from './signables/Signable.js';
import DataDirectoryType from './signables/pe/DataDirectoryType.js';
import PEFile from './signables/pe/PEFile.js';
import makeIterator from './utils/makeIterator.js';

class AuthenticodeSigner {
	private signer: SignerObject;

	constructor(signer: SignerObject) {
		this.signer = signer;
	}

	public async sign(file: Signable, options?: SignOptions): Promise<Buffer> {
		if (file instanceof PEFile) {
			const certificateTable = file.getDataDirectory(
				DataDirectoryType.CertificateTable
			);

			if (certificateTable != null && certificateTable.exists()) {
				if (!options?.replace) {
					throw new Error('Can not add nested signatures');
				}

				// erase previous signatures
				certificateTable.erase();
				certificateTable.write(0, 0);
			}
		}

		const content = await file.getIndirectData(
			this.signer.digest,
			new pkijs.AlgorithmIdentifier({
				algorithmId: this.signer.getDigestAlgorithmOid().join('.')
			})
		);
		const contentDigest = await this.signer.digest(
			makeIterator(Buffer.from(content.toAsn1().toBER()))
		);

		const attributes = new pkijs.SignedAndUnsignedAttributes({
			type: 0,
			attributes: [
				new pkijs.Attribute({
					type: OID_CONTENT_TYPE.getValue(),
					values: [OID_SPC_INDIRECT_DATA]
				}),
				new pkijs.Attribute({
					type: OID_SIGNING_TIME.getValue(),
					values: [new asn1.UTCTime({ valueDate: new Date() })]
				}),
				new pkijs.Attribute({
					type: OID_SPC_STATEMENT_TYPE.getValue(),
					values: [
						new asn1.Sequence({
							value: [OID_SPC_INDIVIDUAL_SP_KEY_PURPOSE]
						})
					]
				}),
				new pkijs.Attribute({
					type: OID_MESSAGE_DIGEST.getValue(),
					values: [new asn1.OctetString({ valueHex: contentDigest })]
				})
			]
		});

		const signature = await this.signer.sign(
			makeIterator(Buffer.from(attributes.toSchema().toBER()))
		);

		const cert = pkijs.Certificate.fromBER(this.signer.getCertificate());

		const signerInfo = new pkijs.SignerInfo({
			version: 1,
			sid: new pkijs.IssuerAndSerialNumber({
				issuer: cert.issuer,
				serialNumber: cert.serialNumber
			}),
			digestAlgorithm: new pkijs.AlgorithmIdentifier({
				algorithmId: this.signer.getDigestAlgorithmOid().join('.')
			}),
			signatureAlgorithm: new pkijs.AlgorithmIdentifier({
				algorithmId: this.signer.getSignatureAlgorithmOid().join('.')
			}),
			signature: new asn1.OctetString({ valueHex: signature }),
			signedAttrs: attributes
		});

		const signedData = new pkijs.SignedData({
			version: 1,
			digestAlgorithms: [
				new pkijs.AlgorithmIdentifier({
					algorithmId: this.signer.getDigestAlgorithmOid().join('.')
				})
			],
			encapContentInfo: new pkijs.EncapsulatedContentInfo({
				eContentType: OID_SPC_INDIRECT_DATA.getValue(),
				eContent: new asn1.OctetString({
					valueHex: content.toAsn1().toBER()
				})
			}),
			signerInfos: [signerInfo],
			certificates: [cert]
		});

		const root = new pkijs.ContentInfo({
			contentType: OID_SIGNED_DATA.getValue(),
			content: signedData.toSchema(true)
		});

		file.setSignature(Buffer.from(root.toSchema().toBER()));

		return file.getFile();
	}
}

export default AuthenticodeSigner;

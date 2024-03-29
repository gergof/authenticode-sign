import asn1 from 'asn1js';
import pkijs from 'pkijs';
import pvtsutils from 'pvtsutils';

import SignOptions from './SignOptions.js';
import SignerObject from './SignerObject.js';
import {
	OID_CONTENT_TYPE,
	OID_MESSAGE_DIGEST,
	OID_RFC3161_COUNTER_SIGNATURE,
	OID_SIGNED_DATA,
	OID_SIGNING_TIME,
	OID_SPC_INDIRECT_DATA,
	OID_SPC_INDIVIDUAL_SP_KEY_PURPOSE,
	OID_SPC_NESTED_SIGNATURE,
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
				if (options?.replace) {
					// replace existing signature, clear certificate table
					certificateTable.erase();
					certificateTable.write(0, 0);
				} else if (!options?.nest) {
					throw new Error(
						'Certificate table already exists but neither replace or nest option was provided'
					);
				}
			} else {
				if (options?.nest) {
					throw new Error(
						'Nest option provided but certificate table does not exist'
					);
				}
			}
		}

		const content = await file.getIndirectData(
			this.signer.digest,
			new pkijs.AlgorithmIdentifier({
				algorithmId: this.signer.getDigestAlgorithmOid()
			})
		);
		const contentDigest = await this.signer.digest(
			makeIterator(Buffer.from(content.toAsn1().valueBlock.toBER()))
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
		attributes.encodedValue = attributes.toSchema().toBER();
		const attributesView = pvtsutils.BufferSourceConverter.toUint8Array(
			attributes.encodedValue
		);
		attributesView[0] = 0x31;

		const signature = await this.signer.sign(
			makeIterator(Buffer.from(attributes.encodedValue))
		);

		const cert = pkijs.Certificate.fromBER(this.signer.getCertificate());
		const intermediateCerts =
			this.signer
				.getIntermediateCertificates?.()
				.map(binaryCert => pkijs.Certificate.fromBER(binaryCert)) || [];

		const signerInfo = new pkijs.SignerInfo({
			version: 1,
			sid: new pkijs.IssuerAndSerialNumber({
				issuer: cert.issuer,
				serialNumber: cert.serialNumber
			}),
			digestAlgorithm: new pkijs.AlgorithmIdentifier({
				algorithmId: this.signer.getDigestAlgorithmOid()
			}),
			signatureAlgorithm: new pkijs.AlgorithmIdentifier({
				algorithmId: this.signer.getSignatureAlgorithmOid()
			}),
			signature: new asn1.OctetString({ valueHex: signature }),
			signedAttrs: attributes
		});

		if (this.signer.timestamp) {
			// timestamp the signature
			signerInfo.unsignedAttrs = new pkijs.SignedAndUnsignedAttributes({
				type: 1,
				attributes: [await this.timestampSignature(signature)]
			});
		}

		const signedData = new pkijs.SignedData({
			version: 1,
			digestAlgorithms: [
				new pkijs.AlgorithmIdentifier({
					algorithmId: this.signer.getDigestAlgorithmOid()
				})
			],
			encapContentInfo: new pkijs.EncapsulatedContentInfo({
				eContentType: OID_SPC_INDIRECT_DATA.getValue(),
				eContent: content.toAsn1() as any
			}),
			signerInfos: [signerInfo],
			certificates: [cert, ...intermediateCerts]
		});

		const root = new pkijs.ContentInfo({
			contentType: OID_SIGNED_DATA.getValue(),
			content: signedData.toSchema()
		});

		if (options?.nest) {
			// nest signature into an existing signature
			const existingSignature = pkijs.ContentInfo.fromBER(
				file.getSignature()
			);
			const existingSignedData = new pkijs.SignedData();
			existingSignedData.fromSchema(existingSignature.content);

			// check if unsigned attributes exist
			if (!existingSignedData.signerInfos[0].unsignedAttrs) {
				existingSignedData.signerInfos[0].unsignedAttrs =
					new pkijs.SignedAndUnsignedAttributes({
						type: 1,
						attributes: []
					});
			}

			// check if a nested attribute already exists
			const existingNestedAttribute =
				existingSignedData.signerInfos[0].unsignedAttrs.attributes.find(
					attr => attr.type == OID_SPC_NESTED_SIGNATURE.getValue()
				);

			if (existingNestedAttribute) {
				existingNestedAttribute.values.push(this.getRootSchema(root));
			} else {
				existingSignedData.signerInfos[0].unsignedAttrs.attributes.push(
					new pkijs.Attribute({
						type: OID_SPC_NESTED_SIGNATURE.getValue(),
						values: [this.getRootSchema(root)]
					})
				);
			}

			const newRoot = new pkijs.ContentInfo({
				contentType: OID_SIGNED_DATA.getValue(),
				content: existingSignedData.toSchema()
			});

			file.setSignature(Buffer.from(this.getRootSchema(newRoot).toBER()));
		} else {
			file.setSignature(Buffer.from(this.getRootSchema(root).toBER()));
		}

		return file.getFile();
	}

	private getRootSchema(root: pkijs.ContentInfo) {
		const schema = root.toSchema();

		// hack version back to v1
		const version = Buffer.alloc(1);
		version.writeUInt8(1);
		(
			schema as any
		).valueBlock.value[1].valueBlock.value[0].valueBlock.value[0].valueBlock.valueHex =
			version;

		return schema;
	}

	private async timestampSignature(
		signature: Buffer
	): Promise<pkijs.Attribute> {
		if (!this.signer.timestamp) {
			throw new Error('Timestamp function not present on signer object');
		}

		const signatureDigest = await this.signer.digest(
			makeIterator(signature)
		);

		const timestampRequest = new pkijs.TimeStampReq({
			version: 1,
			messageImprint: new pkijs.MessageImprint({
				hashAlgorithm: new pkijs.AlgorithmIdentifier({
					algorithmId: this.signer.getDigestAlgorithmOid()
				}),
				hashedMessage: new asn1.OctetString({
					valueHex: signatureDigest
				})
			}),
			certReq: true
		});

		const result = await this.signer.timestamp(
			Buffer.from(timestampRequest.toSchema().toBER())
		);

		const timestampResponse = pkijs.TimeStampResp.fromBER(result);

		if (
			timestampResponse.status.status != pkijs.PKIStatus.granted &&
			timestampResponse.status.status != pkijs.PKIStatus.grantedWithMods
		) {
			throw new Error(
				'Timestamping rejected: ' +
					timestampResponse.status.statusStrings
						?.map(str => str.getValue())
						.join(',')
			);
		}

		if (!timestampResponse.timeStampToken?.content) {
			throw new Error('Token not present on timestamp response');
		}

		return new pkijs.Attribute({
			type: OID_RFC3161_COUNTER_SIGNATURE.getValue(),
			values: [timestampResponse.timeStampToken.toSchema()]
		});
	}
}

export default AuthenticodeSigner;

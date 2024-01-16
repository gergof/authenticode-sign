import asn1 from 'asn1js';
import pkijs from 'pkijs';

import { DigestFn } from '../../SignerObject.js';
import { OID_SPC_PE_IMAGE_DATA } from '../../asn1/OIDs.js';
import SpcAttributeTypeAndOptionalValue from '../../asn1/SpcAttributeTypeAndOptionalValue.js';
import SpcIndirectDataContent from '../../asn1/SpcIndirectDataContent.js';
import SpcLink, { SpcLinkType } from '../../asn1/SpcLink.js';
import SpcPeImageData from '../../asn1/SpcPeImageData.js';
import SpcString from '../../asn1/SpcString.js';
import char from '../../utils/char.js';
import padBuffer from '../../utils/padBuffer.js';
import { hiword, loword } from '../../utils/word.js';
import Signable from '../Signable.js';

import DataDirectory from './DataDirectory.js';
import DataDirectoryType from './DataDirectoryType.js';
import PEFormat from './PEFormat.js';

class PEFile extends Signable {
	private buff: Buffer;
	private peHeaderOffset: number;

	constructor(file: Buffer) {
		super();
		this.buff = file;

		const peHeaderOffsetLocation = this.read(0x3c, 0, 4);
		this.peHeaderOffset =
			peHeaderOffsetLocation.readInt32LE(0) & 0xffffffff;

		if (!this.isPEFile()) {
			throw new Error('Not PE file');
		}
	}

	private isPEFile(): boolean {
		const dosHeader = this.read(0, 0, 2);
		if (dosHeader[0] != char('M') || dosHeader[1] != char('Z')) {
			return false;
		}

		const peHeader = this.read(this.peHeaderOffset, 0, 4);
		if (
			peHeader[0] != char('P') ||
			peHeader[1] != char('E') ||
			peHeader[2] != 0 ||
			peHeader[3] != 0
		) {
			return false;
		}

		return true;
	}

	public read(base: number, offset: number, length: number): Buffer {
		return this.buff.subarray(base + offset, base + offset + length);
	}

	public readWord(base: number, offset: number): number {
		return this.read(base, offset, 2).readUInt16LE();
	}

	public readDWord(base: number, offset: number): number {
		return this.read(base, offset, 4).readUInt32LE();
	}

	public write(base: number, data: Buffer) {
		data.copy(this.buff, base);
	}

	public getSize() {
		return this.buff.byteLength;
	}

	public getFormat(): PEFormat {
		return this.readWord(this.peHeaderOffset, 24);
	}

	public getNumberOfRvaAndSizes() {
		return this.readDWord(
			this.peHeaderOffset,
			this.getFormat() == PEFormat.PE32 ? 116 : 132
		);
	}

	public getDataDirectoryOffset() {
		return (
			this.peHeaderOffset +
			(this.getFormat() == PEFormat.PE32 ? 120 : 136)
		);
	}

	public getDataDirectory(type: DataDirectoryType): DataDirectory | null {
		if (type >= this.getNumberOfRvaAndSizes()) {
			return null;
		}

		return new DataDirectory(this, type);
	}

	public writeDataDirectory(type: DataDirectoryType, data: Buffer) {
		const directory = this.getDataDirectory(type);

		if (directory == null) {
			throw new Error(
				'No space allocated in the data directories index for directory ' +
					type
			);
		}

		if (!directory.exists()) {
			const offset = this.getSize();
			this.buff = Buffer.concat([this.buff, data]);
			directory.write(offset, data.byteLength);
		} else {
			if (directory.getSize() == data.byteLength) {
				// same size => overwrite
				data.copy(this.buff, directory.getVirtualAddress());
			} else if (
				data.length < directory.getSize() &&
				type != DataDirectoryType.CertificateTable
			) {
				// smaller => erase and rewrite in-place
				// doesn't work with cert table
				directory.erase();
				data.copy(this.buff, directory.getVirtualAddress());
				directory.write(directory.getVirtualAddress(), data.byteLength);
			} else if (directory.isTrailing()) {
				// end of file => erase and write to end
				this.buff = Buffer.concat([
					this.buff.subarray(0, directory.getVirtualAddress()),
					data
				]);
			} else {
				if (type == DataDirectoryType.CertificateTable) {
					throw new Error(
						'The certificate table is not at the end of the file and can not be moved without invalidating the signature'
					);
				}

				// larger => erase and relocate at end

				directory.erase();
				const offset = this.getSize();
				this.buff = Buffer.concat([this.buff, data]);
				directory.write(offset, data.byteLength);
			}
		}

		this.updateChecksum();
	}

	public updateChecksum() {
		const buffer = Buffer.alloc(4);
		buffer.writeUInt32LE(this.calculateChecksum());

		this.write(this.peHeaderOffset + 88, buffer);
	}

	public calculateChecksum() {
		const checksumOffset = this.peHeaderOffset + 88;
		let checksum = 0;

		for (let i = 0; i < this.getSize(); i += 2) {
			if (i != checksumOffset && i != checksumOffset + 2) {
				// skip checksum
				const dword = this.readWord(0, i);
				checksum += dword;
				checksum = loword(loword(checksum) + hiword(checksum));
			}
		}

		checksum = loword(loword(checksum) + hiword(checksum));
		checksum += this.getSize();

		return checksum;
	}

	public getFile() {
		return this.buff;
	}

	public calculateDigest(digest: DigestFn) {
		function* digestDataGenerator(pefile: PEFile) {
			let pos = 0;

			// digest from the beginning to the checksum field
			const checksumOffset = pefile.peHeaderOffset + 88;
			yield pefile.buff.subarray(pos, checksumOffset);
			pos = checksumOffset + 4;

			// digest from the end of the checksum to the beginning of the certificate table entry
			const certificateTableOffset =
				pefile.getDataDirectoryOffset() +
				8 * DataDirectoryType.CertificateTable;
			yield pefile.buff.subarray(pos, certificateTableOffset);
			pos = certificateTableOffset + 8;

			// digest from the end of the certificate table entry to the beginning of the certificate table
			const certificateTable = pefile.getDataDirectory(
				DataDirectoryType.CertificateTable
			);
			if (certificateTable != null && certificateTable.exists()) {
				yield pefile.buff.subarray(
					pos,
					certificateTable.getVirtualAddress()
				);
				pos =
					certificateTable.getVirtualAddress() +
					certificateTable.getSize();
			}

			// diest from the end of the certificate table to the end of the file
			yield pefile.buff.subarray(pos, pefile.buff.byteLength);

			if (certificateTable == null || !certificateTable.exists()) {
				// if the file has never been signed before, update the digest as if the file was padded on a 8 byte boundary
				const paddingLength = 8 - (pefile.getSize() % 8);
				yield Buffer.alloc(paddingLength);
			}
		}

		return digest(digestDataGenerator(this));
	}

	public async getIndirectData(
		digest: DigestFn,
		digestAlgorithm: pkijs.AlgorithmIdentifier
	) {
		const fileDigest = await this.calculateDigest(digest);

		return new SpcIndirectDataContent(
			new SpcAttributeTypeAndOptionalValue(
				OID_SPC_PE_IMAGE_DATA,
				new SpcPeImageData(
					new SpcLink(SpcLinkType.file, new SpcString(''))
				)
			),
			new pkijs.DigestInfo({
				digestAlgorithm: digestAlgorithm,
				digest: new asn1.OctetString({ valueHex: fileDigest })
			})
		);
	}

	public setSignature(signedData: pkijs.SignedData) {
		const content = Buffer.from(signedData.toSchema().toBER());
		const paddedContent = padBuffer(content, 8);

		const signature = Buffer.alloc(paddedContent.byteLength + 8);
		signature.writeInt32LE(signature.byteLength, 0);
		signature.writeInt16LE(0x0200, 4); // revision 2
		signature.writeInt16LE(0x0002, 6); // pkcs signed data
		paddedContent.copy(signature, 8);

		const certificateTable = this.getDataDirectory(
			DataDirectoryType.CertificateTable
		);
		if (certificateTable == null || !certificateTable.exists()) {
			// pad file
			this.buff = padBuffer(this.buff, 8);
		}

		this.writeDataDirectory(DataDirectoryType.CertificateTable, signature);
	}
}

export default PEFile;
import asn1 from 'asn1js';

import Asn1Wrapper from './Asn1Wrapper.js';
import SpcLink from './SpcLink.js';

class SpcPeImageData extends Asn1Wrapper {
	private file: SpcLink;

	constructor(file: SpcLink) {
		super();

		this.file = file;
	}

	public toAsn1() {
		return new asn1.Sequence({
			value: [
				new asn1.BitString({
					valueHex: Buffer.alloc(0)
				}),
				this.file.toAsn1()
			]
		});
	}
}

export default SpcPeImageData;

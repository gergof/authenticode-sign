import asn1 from 'asn1js';

import Asn1Wrapper from './Asn1Wrapper.js';

class SpcString extends Asn1Wrapper {
	private utf8String: asn1.BmpString;

	constructor(utf8String: string) {
		super();

		this.utf8String = new asn1.BmpString({
			value: utf8String
		});
	}

	public toAsn1() {
		return new asn1.Primitive({
			idBlock: {
				tagClass: 3,
				tagNumber: 0
			},
			valueHex: this.utf8String.valueBlock.valueHex
		});
	}
}

export default SpcString;

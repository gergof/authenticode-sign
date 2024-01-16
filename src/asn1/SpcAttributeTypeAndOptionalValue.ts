import asn1 from 'asn1js';

import Asn1Wrapper from './Asn1Wrapper.js';

class SpcAttributeTypeAndOptionalValue extends Asn1Wrapper {
	private type: asn1.ObjectIdentifier;
	private value: asn1.Any;

	constructor(type: asn1.ObjectIdentifier, value: asn1.Any | Asn1Wrapper) {
		super();

		this.type = type;
		this.value = value instanceof Asn1Wrapper ? value.toAsn1() : value;
	}

	public toAsn1() {
		return new asn1.Sequence({
			value: [this.type, this.value]
		});
	}
}

export default SpcAttributeTypeAndOptionalValue;

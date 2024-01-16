import asn1 from 'asn1js';
import pkijs from 'pkijs';

import Asn1Wrapper from './Asn1Wrapper.js';
import SpcAttributeTypeAndOptionalValue from './SpcAttributeTypeAndOptionalValue.js';

class SpcIndirectDataContent extends Asn1Wrapper {
	private data: SpcAttributeTypeAndOptionalValue;
	private digest: pkijs.DigestInfo;

	constructor(
		data: SpcAttributeTypeAndOptionalValue,
		digest: pkijs.DigestInfo
	) {
		super();

		this.data = data;
		this.digest = digest;
	}

	toAsn1() {
		return new asn1.Sequence({
			value: [this.data.toAsn1(), this.digest.toSchema()]
		});
	}
}

export default SpcIndirectDataContent;

import asn1 from 'asn1js';

import Asn1Wrapper from './Asn1Wrapper.js';
import SpcString from './SpcString.js';

export enum SpcLinkType {
	url = 0,
	moniker = 1,
	file = 2
}

class SpcLink extends Asn1Wrapper {
	private tag: SpcLinkType;
	private content: asn1.Primitive;

	constructor(type: SpcLinkType.url, url: asn1.IA5String);
	constructor(type: SpcLinkType.moniker, moniker: never);
	constructor(type: SpcLinkType.file, file: SpcString);
	constructor(type: SpcLinkType, content: asn1.IA5String | SpcString) {
		super();

		this.tag = type;

		if (content instanceof Asn1Wrapper) {
			this.content = content.toAsn1();
		} else {
			this.content = content;
		}
	}

	public toAsn1() {
		if(this.tag == SpcLinkType.file) {
			return new asn1.Constructed({
				idBlock: {
					tagClass: 3,
					tagNumber: this.tag
				},
				value: [this.content]
			})
		}

		return new asn1.Primitive({
			idBlock: {
				tagClass: 3,
				tagNumber: this.tag
			},
			valueHex: this.content.valueBlock.valueHex
		});
	}
}

export default SpcLink;

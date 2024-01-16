import asn1 from 'asn1js';

abstract class Asn1Wrapper {
	public abstract toAsn1(): asn1.Constructed | asn1.Primitive;
}

export default Asn1Wrapper;

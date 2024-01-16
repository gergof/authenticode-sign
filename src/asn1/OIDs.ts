import asn1 from 'asn1js';

const OID = (id: string) => new asn1.ObjectIdentifier({ value: id });

export const OID_SPC_INDIRECT_DATA = OID('1.3.6.1.4.1.311.2.1.4');
export const OID_SPC_PE_IMAGE_DATA = OID('1.3.6.1.4.1.311.2.1.15');
export const OID_CONTENT_TYPE = OID('1.2.840.113549.1.9.3');
export const OID_SPC_STATEMENT_TYPE = OID('1.3.6.1.4.1.311.2.1.11');
export const OID_SPC_INDIVIDUAL_SP_KEY_PURPOSE = OID('1.3.6.1.4.1.311.2.1.21');
export const OID_MESSAGE_DIGEST = OID('1.2.840.113549.1.9.4');
export const OID_SIGNED_DATA = OID('1.2.840.113549.1.7.2');
export const OID_SIGNING_TIME = OID('1.2.840.113549.1.9.5');

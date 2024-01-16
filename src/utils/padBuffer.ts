const padBuffer = (buff: Buffer, multiple: number) => {
	if (buff.byteLength % multiple == 0) {
		return buff;
	}

	return Buffer.concat([
		buff,
		Buffer.alloc(multiple - (buff.byteLength % multiple))
	]);
};

export default padBuffer;

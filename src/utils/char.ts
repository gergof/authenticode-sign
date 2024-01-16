const char = (char: string): number => {
	if (char.length != 1) {
		throw new Error('Char must be exactly 1 character long');
	}

	return char.charCodeAt(0);
};

export default char;

export const loword = (n: number): number => {
	return n & 0xffff;
};

export const hiword = (n: number): number => {
	return (n >> 16) & 0xffff;
};

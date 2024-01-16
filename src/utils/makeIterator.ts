const makeIterator = <T>(data: T): Iterator<T> => {
	let done = false;

	return {
		next() {
			if (done) {
				return {
					done: true,
					value: undefined
				};
			}

			done = true;
			return {
				done: false,
				value: data
			};
		}
	};
};

export default makeIterator;

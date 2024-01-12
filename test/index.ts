/* eslint-disable no-console */ 
import AuthenticodeSign from '../src/index.js';

const main = async () => {
	if(AuthenticodeSign(1,2) == 3) {
		console.log('ok')
	}
	else {
		console.log('not ok')
	}
}

main();
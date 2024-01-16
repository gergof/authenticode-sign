import PEFile from './PEFile.js';

class DataDirectory {
	private peFile: PEFile;
	private index: number;

	constructor(peFile: PEFile, index: number) {
		this.peFile = peFile;
		this.index = index;
	}

	public getVirtualAddress() {
		return this.peFile.readDWord(
			this.peFile.getDataDirectoryOffset(),
			this.index * 8
		);
	}

	public getSize() {
		return this.peFile.readDWord(
			this.peFile.getDataDirectoryOffset(),
			this.index * 8 + 4
		);
	}

	public exists() {
		return this.getVirtualAddress() != 0 && this.getSize() != 0;
	}

	public erase() {
		this.peFile.write(
			this.getVirtualAddress(),
			Buffer.alloc(this.getSize())
		);
	}

	public isTrailing() {
		return (
			this.getVirtualAddress() + this.getSize() == this.peFile.getSize()
		);
	}

	public write(address: number, size: number) {
		const buffer = Buffer.alloc(8);
		buffer.writeInt32LE(address);
		buffer.writeInt32LE(size, 4);
		this.peFile.write(
			this.peFile.getDataDirectoryOffset() + this.index * 8,
			buffer
		);
	}
}

export default DataDirectory;

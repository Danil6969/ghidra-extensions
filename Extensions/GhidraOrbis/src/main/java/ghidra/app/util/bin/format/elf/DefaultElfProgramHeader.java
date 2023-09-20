package ghidra.app.util.bin.format.elf;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

public class DefaultElfProgramHeader extends ElfProgramHeader {

	public DefaultElfProgramHeader(BinaryReader reader, ElfHeader header) throws IOException {
		super(reader, header);
	}

	public static ElfProgramHeader createElfProgramHeader(BinaryReader reader,
														  ElfHeader header) throws IOException {
		ElfProgramHeader elfProgramHeader = new ElfProgramHeader(reader, header);
		return elfProgramHeader;
	}
}

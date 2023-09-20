package ghidra.app.util.bin.format.elf;

import java.io.IOException;
import java.lang.reflect.Method;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.exception.AssertException;

public class DefaultElfSymbolTable extends ElfSymbolTable {

	public DefaultElfSymbolTable(BinaryReader reader, ElfHeader header, ElfSectionHeader symbolTableSection, long fileOffset, long addrOffset, long length, long entrySize, ElfStringTable stringTable, int[] symbolSectionIndexTable, boolean isDynamic) throws IOException {
		super(reader, header, symbolTableSection, fileOffset, addrOffset, length, entrySize, stringTable, symbolSectionIndexTable, isDynamic);
	}

	public static ElfSymbolTable createElfSymbolTable(BinaryReader reader,
													  ElfHeader header, ElfSectionHeader symbolTableSection, long fileOffset, long addrOffset,
													  long length, long entrySize, ElfStringTable stringTable, boolean isDynamic)
			throws IOException {
		ElfSymbolTable elfSymbolTable = new ElfSymbolTable(
			reader, header, symbolTableSection, fileOffset, addrOffset,
			length, entrySize, stringTable, null, isDynamic);
		return elfSymbolTable;
	}

	protected void initElfSymbolTable(BinaryReader reader, ElfHeader header,
			ElfSectionHeader symbolTableSection, long fileOffset, long addrOffset, long length,
			long entrySize, ElfStringTable stringTable, boolean isDynamic) {
		try {
			Method m = ElfSymbolTable.class.getDeclaredMethod(
				"initElfSymbolTable", BinaryReader.class, ElfHeader.class,
				ElfSectionHeader.class, long.class, long.class, long.class, long.class,
				ElfStringTable.class, boolean.class);
			m.setAccessible(true);
			m.invoke(this, reader, header, symbolTableSection, fileOffset, addrOffset,
				length, entrySize, stringTable, isDynamic);
			m.setAccessible(false);
		} catch (Exception e) {
			throw new AssertException(e);
		}
	}
}

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;

public class GetKallsymName extends GhidraScript {
	int pointerSize;
	Memory memory;
	SymbolTable symbolTable;
	Address kallsyms_token_table;
	Address kallsyms_token_index;
	Address kallsyms_names;
	Address kallsyms_markers;
	Address kallsyms_addresses;
	long kallsyms_num_syms;

	@Override
	public void run() throws Exception {
		try {
			if (!init()) return;
			long position = get_symbol_pos(currentAddress);
			if (position < 0) return;
			long marker = memory.getLong(kallsyms_markers.add((position >> 8) * pointerSize));
			Address name = kallsyms_names.add(marker);
			long offset = 0;
			while (offset < (position & 0xff)) {
				long length = Byte.toUnsignedLong(memory.getByte(name));
				name = name.add(length + 1);
				offset++;
			}
			StringBuilder result = new StringBuilder();
			kallsyms_expand_symbol(name.subtract(kallsyms_names), result);
			result.append('\n');
			print(result.toString());
		}
		catch (Exception e) {}
	}

	boolean init() {
		try {
			pointerSize = currentProgram.getDefaultPointerSize();
			memory = currentProgram.getMemory();
			symbolTable = currentProgram.getSymbolTable();
			Symbol symbol = getSingleSymbol("kallsyms_token_table");
			if (symbol == null) return false;
			kallsyms_token_table = symbol.getAddress();
			symbol = getSingleSymbol("kallsyms_token_index");
			if (symbol == null) return false;
			kallsyms_token_index = symbol.getAddress();
			symbol = getSingleSymbol("kallsyms_names");
			if (symbol == null) return false;
			kallsyms_names = symbol.getAddress();
			symbol = getSingleSymbol("kallsyms_markers");
			if (symbol == null) return false;
			kallsyms_markers = symbol.getAddress();
			symbol = getSingleSymbol("kallsyms_addresses");
			if (symbol == null) return false;
			kallsyms_addresses = symbol.getAddress();
			symbol = getSingleSymbol("kallsyms_num_syms");
			if (symbol == null) return false;
			kallsyms_num_syms = memory.getLong(symbol.getAddress());
			return true;
		}
		catch (Exception e) {
			return false;
		}
	}

	Symbol getSingleSymbol(String name) {
		SymbolIterator iter = symbolTable.getSymbols(name);
		if (!iter.hasNext()) return null;
		Symbol symbol = iter.next();
		if (iter.hasNext()) return null;
		return symbol;
	}

	private long get_symbol_pos(Address address) {
		try {
			if (address == null) {
				return -1;
			}
			long offset1 = address.getOffset();
			for (long i = 0; i < kallsyms_num_syms * pointerSize; i += pointerSize) {
				long offset2 = memory.getLong(kallsyms_addresses.add(i));
				if (offset1 == offset2) {
					return i / pointerSize;
				}
			}
			return -1;
		}
		catch (Exception e) {
			return -1;
		}
	}

	private void kallsyms_expand_symbol(long offset, StringBuilder result) {
		try {
			boolean skipped_first = false;
			result.setLength(0);
			Address data = kallsyms_names.add(offset);
			int len = Byte.toUnsignedInt(memory.getByte(data));
			byte[] values = new byte[len];
			data = data.add(1);
			memory.getBytes(data,values);
			for (byte value : values) {
				long index = memory.getShort(kallsyms_token_index.add(Byte.toUnsignedLong(value) * 2));
				Address tptr = kallsyms_token_table.add(index);
				byte b = memory.getByte(tptr);
				while (b != 0) {
					if (!skipped_first) {
						skipped_first = true;
						tptr = tptr.add(1);
						b = memory.getByte(tptr);
						continue;
					}
					result.append((char)b);
					tptr = tptr.add(1);
					b = memory.getByte(tptr);
				}
			}
		}
		catch (Exception e) {}
	}
}

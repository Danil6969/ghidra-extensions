package ghidra.app.cmd.data.rtti.borland.delphi.datatype;

import ghidra.app.cmd.data.rtti.borland.delphi.util.ListingUtils;
import ghidra.app.cmd.data.rtti.borland.delphi.util.MemoryUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

public class TVmtFieldTable_1 {
	public static StructureDataType getDataType(CategoryPath path, DataTypeManager manager) {
		StructureDataType dt = new StructureDataType(path, "TVmtFieldTable_1", 0, manager);
		StructureDataType entryDT = TVmtFieldExEntry.getDataType(path, manager);
		dt.add(Word.getDataType(path, manager), "ExCount", "");
		dt.add(new ArrayDataType(entryDT, 0, entryDT.getLength()), "ExEntry", "");
		return dt;
	}

	public static Address putObject(Address address, CategoryPath path, Program program) {
		try {
			ProgramBasedDataTypeManager manager = program.getDataTypeManager();
			ListingUtils.deleteCreateData(address, getDataType(path, manager), program);
			TypedefDataType wordDT = Word.getDataType(path, manager);
			long count = MemoryUtil.readNumber(address, wordDT.getLength(), program);
			address = address.add(wordDT.getLength());
			for (int i = 0; i < count; i++) {
				address = TVmtFieldExEntry.putObject(address, path, program);
			}
			return address;
		} catch (MemoryAccessException e) {
			return null;
		}
	}
}

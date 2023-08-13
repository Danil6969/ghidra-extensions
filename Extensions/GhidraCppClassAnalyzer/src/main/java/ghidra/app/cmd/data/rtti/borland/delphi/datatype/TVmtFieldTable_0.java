package ghidra.app.cmd.data.rtti.borland.delphi.datatype;

import ghidra.app.cmd.data.rtti.borland.delphi.util.ListingUtils;
import ghidra.app.cmd.data.rtti.borland.delphi.util.MemoryUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

public class TVmtFieldTable_0 {
	public static StructureDataType getDataType(CategoryPath path, DataTypeManager manager) {
		StructureDataType dt = new StructureDataType(path, "TVmtFieldTable_0", 0, manager);
		StructureDataType entryDT = TVmtFieldEntry.getDataType(path, manager);
		dt.add(Word.getDataType(path, manager), "Count", "");
		dt.add(PointerDataType.dataType, "ClassTab", "");
		dt.add(new ArrayDataType(entryDT, 0, entryDT.getLength()), "Entry", "");
		return dt;
	}

	public static Address putObject(Address address, CategoryPath path, Program program) {
		try {
			ProgramBasedDataTypeManager manager = program.getDataTypeManager();
			ListingUtils.deleteCreateData(address, getDataType(path, manager), program);
			TypedefDataType wordDT = Word.getDataType(path, manager);
			PointerDataType pointerDT = PointerDataType.dataType;
			long count = MemoryUtil.readNumber(address, wordDT.getLength(), program);
			address = address.add(wordDT.getLength());
			address = address.add(pointerDT.getLength());
			for (int i = 0; i < count; i++) {
				address = TVmtFieldEntry.putObject(address, path, program);
			}
			return TVmtFieldTable_1.putObject(address, path, program);
		} catch (MemoryAccessException e) {
			return null;
		}
	}
}

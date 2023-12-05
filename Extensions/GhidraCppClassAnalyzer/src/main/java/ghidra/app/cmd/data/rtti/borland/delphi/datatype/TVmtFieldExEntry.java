package ghidra.app.cmd.data.rtti.borland.delphi.datatype;

import ghidra.app.cmd.data.rtti.borland.delphi.util.ListingUtils;
import ghidra.app.cmd.data.rtti.borland.delphi.util.MemoryUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

public class TVmtFieldExEntry {
	public static StructureDataType getDataType(CategoryPath path, DataTypeManager manager) {
		StructureDataType dt = new StructureDataType(path, "TVmtFieldExEntry", 0, manager);
		dt.add(Byte.getDataType(path, manager), "Flags", "");
		dt.add(PPTypeInfo.getDataType(path, manager), "TypeRef", "Pointer to RTTI record");
		dt.add(Cardinal.getDataType(path, manager), "Offset", "");
		dt.add(new ArrayDataType(CharDataType.dataType, 0, 1), "Name", "");
		return dt;
	}

	public static Address putObject(Address address, CategoryPath path, Program program) {
		try {
			ProgramBasedDataTypeManager manager = program.getDataTypeManager();
			StructureDataType thisDT = getDataType(path, manager);
			TypedefDataType byteDT = Byte.getDataType(path, manager);
			ListingUtils.deleteCreateData(address, thisDT, program);
			address = address.add(thisDT.getLength());
			Data data = ListingUtils.deleteCreateData(address, PascalString255DataType.dataType, program);
			address = address.add(data.getLength());
			long count = MemoryUtil.readNumber(address, byteDT.getLength(), program);
			address = address.add(byteDT.getLength());
			for (int i = 1; i < count; i++) {
				address = address.add(1);
			}
			return address;
		} catch (MemoryAccessException e) {
			return null;
		}
	}
}

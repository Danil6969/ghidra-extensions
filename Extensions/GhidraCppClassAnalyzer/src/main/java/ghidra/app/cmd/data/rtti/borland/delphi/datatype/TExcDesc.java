package ghidra.app.cmd.data.rtti.borland.delphi.datatype;

import ghidra.app.cmd.data.rtti.borland.delphi.util.ListingUtils;
import ghidra.app.cmd.data.rtti.borland.delphi.util.MemoryUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;

public class TExcDesc {
	public static StructureDataType getDataType(CategoryPath path, DataTypeManager manager) {
		StructureDataType dt = new StructureDataType(path, "TExcDesc", 0, manager);
		StructureDataType entryDT = TExcDescEntry.getDataType(path, manager);
		TypedefDataType integerDT = Integer.getDataType(path, manager);
		dt.add(integerDT, "Cnt", "Number of exception classes defined in an \"except on...\"-block");
		dt.add(new ArrayDataType(entryDT, 0, entryDT.getLength()), "ExcTab", "Table of on-definitions and there handlers in an \"except on...\"-block");
		return dt;
	}

	public static Address putObject(Address address, CategoryPath path, Program program) {
		try {
			ProgramBasedDataTypeManager manager = program.getDataTypeManager();
			StructureDataType thisDT = getDataType(path, manager);
			TypedefDataType integerDT = Integer.getDataType(path, manager);
			ListingUtils.deleteCreateData(address, thisDT, program);
			long count = MemoryUtil.readNumber(address, integerDT.getLength(), program);
			address = address.add(thisDT.getLength());
			for (int i = 0; i < count; i++) {
				address = TExcDescEntry.putObject(address, path, program);
			}
			return address;
		} catch (MemoryAccessException e) {
			return null;
		}
	}
}

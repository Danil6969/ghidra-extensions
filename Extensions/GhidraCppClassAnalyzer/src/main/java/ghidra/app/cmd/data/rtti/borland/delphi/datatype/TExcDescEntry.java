package ghidra.app.cmd.data.rtti.borland.delphi.datatype;

import ghidra.app.cmd.data.rtti.borland.delphi.util.ListingUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;

public class TExcDescEntry {
	public static StructureDataType getDataType(CategoryPath path, DataTypeManager manager) {
		StructureDataType dt = new StructureDataType(path, "TExcDesc", 0, manager);
		TypedefDataType pointerDT = Integer.getDataType(path, manager);
		dt.add(pointerDT, "Table", "");
		dt.add(pointerDT, "Handler", "");
		return dt;
	}

	public static Address putObject(Address address, CategoryPath path, Program program) {
		ProgramBasedDataTypeManager manager = program.getDataTypeManager();
		StructureDataType thisDT = getDataType(path, manager);
		ListingUtils.deleteCreateData(address, thisDT, program);
		address = address.add(thisDT.getLength());
		return address;
	}
}

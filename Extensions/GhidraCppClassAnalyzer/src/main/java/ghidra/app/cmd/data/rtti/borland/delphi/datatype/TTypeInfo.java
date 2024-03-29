package ghidra.app.cmd.data.rtti.borland.delphi.datatype;

import ghidra.app.cmd.data.rtti.borland.delphi.util.ListingUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;

public class TTypeInfo {
	public static StructureDataType getDataType(CategoryPath path, DataTypeManager manager) {
		StructureDataType dt = new StructureDataType(path, "TTypeInfo", 0, manager);
		CharDataType charDT = CharDataType.dataType;
		dt.add(TTypeKind.getDataType(path, manager), "Kind", "The kind of type in RTTI terms");
		dt.add(new ArrayDataType(charDT, 0, charDT.getLength()), "Name", "The name of the data type");
		return dt;
	}

	public static Address putObject(Address address, CategoryPath path, Program program) {
		ProgramBasedDataTypeManager manager = program.getDataTypeManager();
		StructureDataType thisDT = getDataType(path, manager);
		ListingUtils.deleteCreateData(address, thisDT, program);
		address = address.add(thisDT.getLength());
		Data data = ListingUtils.deleteCreateData(address, PascalString255DataType.dataType, program);
		address = address.add(data.getLength());
		return address;
	}
}

package ghidra.app.cmd.data.rtti.borland.delphi.datatype;

import ghidra.app.cmd.data.rtti.borland.delphi.util.ListingUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;

public class TTypeInfo {
	public static StructureDataType getDataType(CategoryPath path, DataTypeManager manager) {
		StructureDataType dt = new StructureDataType(path, "TTypeInfo", 0, manager);
		CharDataType charDT = CharDataType.dataType;
		dt.add(TTypeKind.getDataType(path, manager), "Kind", "Type kind");
		dt.add(new ArrayDataType(charDT, 0, charDT.getLength()), "Name", "Type name");
		return dt;
	}

	public static void putObject(Address address, CategoryPath path, Program program) {
		ProgramBasedDataTypeManager manager = program.getDataTypeManager();
		StructureDataType TTypeInfoDT = getDataType(path, manager);
		ListingUtils.deleteCreateData(address, TTypeInfoDT, program);
		ListingUtils.deleteCreateData(address.add(TTypeInfoDT.getLength()), PascalString255DataType.dataType, program);
	}
}

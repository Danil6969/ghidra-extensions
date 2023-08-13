package ghidra.app.cmd.data.rtti.borland.delphi.datatype;

import ghidra.app.cmd.data.rtti.borland.delphi.util.ListingUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;

public class TVmtFieldEntry {
	public static StructureDataType getDataType(CategoryPath path, DataTypeManager manager) {
		StructureDataType dt = new StructureDataType(path, "TVmtFieldEntry", 0, manager);
		CharDataType charDT = CharDataType.dataType;
		dt.add(Cardinal.getDataType(path, manager), "FieldOffset", "Offset of the field from the start of the class data");
		dt.add(Word.getDataType(path, manager), "TypeIndex", "Type of the field");
		dt.add(new ArrayDataType(charDT, 0, charDT.getLength()), "Name", "Name of the field");
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

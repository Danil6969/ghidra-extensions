package ghidra.app.cmd.data.rtti.borland.delphi.datatype;

import ghidra.program.model.data.*;

public class TVmtFieldExEntry {
	public static StructureDataType getDataType(CategoryPath path, DataTypeManager manager) {
		StructureDataType dt = new StructureDataType(path, "TVmtFieldExEntry", 0, manager);
		dt.add(Byte.getDataType(path, manager), "Flags", "");
		dt.add(PPTypeInfo.getDataType(path, manager), "TypeRef", "");
		dt.add(Cardinal.getDataType(path, manager), "Offset", "");
		dt.add(new ArrayDataType(CharDataType.dataType, 0, 1), "Name", "");
		return dt;
	}
}

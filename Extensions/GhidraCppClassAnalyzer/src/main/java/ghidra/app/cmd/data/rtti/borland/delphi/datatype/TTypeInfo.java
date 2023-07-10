package ghidra.app.cmd.data.rtti.borland.delphi.datatype;

import ghidra.program.model.data.*;

public class TTypeInfo {
	public static StructureDataType getDataType(CategoryPath path, DataTypeManager manager) {
		StructureDataType dt = new StructureDataType(path, "TTypeInfo", 0, manager);
		dt.add(TTypeKind.getDataType(path, manager), "Kind", "Type kind");
		dt.add(new ArrayDataType(CharDataType.dataType, 0, 1), "Name", "Type name");
		return dt;
	}
}

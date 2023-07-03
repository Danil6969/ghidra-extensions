package ghidra.app.cmd.data.rtti.borland.delphi;

import ghidra.program.model.data.*;

public class TTypeInfo {
	public static StructureDataType getDataType(CategoryPath path, DataTypeManager manager) {
		StructureDataType TTypeInfoDT = new StructureDataType(path, "TTypeInfo", 0, manager);
		TTypeInfoDT.add(TTypeKind.getDataType(path, manager));
		TTypeInfoDT.add(new ArrayDataType(CharDataType.dataType, 0, -1));
		return TTypeInfoDT;
	}
}

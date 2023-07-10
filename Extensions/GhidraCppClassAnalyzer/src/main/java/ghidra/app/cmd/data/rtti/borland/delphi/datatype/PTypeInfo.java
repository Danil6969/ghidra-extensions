package ghidra.app.cmd.data.rtti.borland.delphi.datatype;

import ghidra.program.model.data.*;

public class PTypeInfo {
	public static TypedefDataType getDataType(CategoryPath path, DataTypeManager manager) {
		PointerDataType dt = new PointerDataType(TTypeInfo.getDataType(path, manager), manager);
		return new TypedefDataType(path, "PTypeInfo", dt, manager);
	}
}

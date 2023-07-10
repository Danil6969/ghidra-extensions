package ghidra.app.cmd.data.rtti.borland.delphi.datatype;

import ghidra.program.model.data.*;

public class PPTypeInfo {
	public static TypedefDataType getDataType(CategoryPath path, DataTypeManager manager) {
		PointerDataType dt = new PointerDataType(PTypeInfo.getDataType(path, manager), manager);
		return new TypedefDataType(path, "PPTypeInfo", dt, manager);
	}
}

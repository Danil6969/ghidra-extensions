package ghidra.app.cmd.data.rtti.borland.delphi.datatype;

import ghidra.program.model.data.*;

public class CodePointer {
	public static TypedefDataType getDataType(CategoryPath path, DataTypeManager manager) {
		PointerDataType dt = new PointerDataType(manager);
		return new TypedefDataType(path, "CodePointer", dt, manager);
	}
}

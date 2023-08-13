package ghidra.app.cmd.data.rtti.borland.delphi.datatype;

import ghidra.program.model.data.*;

public class SizeInt {
	public static TypedefDataType getDataType(CategoryPath path, DataTypeManager manager) {
		TypedefDataType dt = LongInt.getDataType(path, manager);
		if (dt == null) return null;
		return new TypedefDataType(path, "SizeInt", dt, manager);
	}
}

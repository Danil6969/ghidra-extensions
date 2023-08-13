package ghidra.app.cmd.data.rtti.borland.delphi.datatype;

import ghidra.program.model.data.*;

public class Int64 {
	public static TypedefDataType getDataType(CategoryPath path, DataTypeManager manager) {
		LongLongDataType dt = LongLongDataType.dataType;
		return new TypedefDataType(path, "Int64", dt, manager);
	}
}

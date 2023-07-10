package ghidra.app.cmd.data.rtti.borland.delphi.datatype;

import ghidra.program.model.data.*;

public class Integer {
	public static TypedefDataType getDataType(CategoryPath path, DataTypeManager manager) {
		IntegerDataType dt = IntegerDataType.dataType;
		return new TypedefDataType(path, "Integer", dt, manager);
	}
}

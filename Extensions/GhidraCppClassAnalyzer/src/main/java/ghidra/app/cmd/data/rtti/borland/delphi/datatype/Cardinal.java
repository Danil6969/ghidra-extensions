package ghidra.app.cmd.data.rtti.borland.delphi.datatype;

import ghidra.program.model.data.*;

public class Cardinal {
	public static TypedefDataType getDataType(CategoryPath path, DataTypeManager manager) {
		UnsignedIntegerDataType dt = UnsignedIntegerDataType.dataType;
		return new TypedefDataType(path, "Cardinal", dt, manager);
	}
}

package ghidra.app.cmd.data.rtti.borland.delphi.datatype;

import ghidra.program.model.data.*;

public class Byte {
	public static TypedefDataType getDataType(CategoryPath path, DataTypeManager manager) {
		ByteDataType dt = ByteDataType.dataType;
		return new TypedefDataType(path, "Byte", dt, manager);
	}
}

package ghidra.app.cmd.data.rtti.borland.delphi.datatype;

import ghidra.program.model.data.*;

public class PShortString {
	public static TypedefDataType getDataType(CategoryPath path, DataTypeManager manager) {
		PointerDataType dt = new PointerDataType(PascalString255DataType.dataType, manager);
		return new TypedefDataType(path, "PShortString", dt, manager);
	}
}

package ghidra.app.cmd.data.rtti.borland.delphi.datatype;

import ghidra.program.model.data.*;

public class LongInt {
	public static TypedefDataType getDataType(CategoryPath path, DataTypeManager manager) {
		int pointerLength = PointerDataType.dataType.getLength();
		if (pointerLength == 4) {
			TypedefDataType dt = Integer.getDataType(path, manager);
			return new TypedefDataType(path, "LongInt", dt, manager);
		}
		else if (pointerLength == 8) {
			TypedefDataType dt = Int64.getDataType(path, manager);
			return new TypedefDataType(path, "LongInt", dt, manager);
		}
		return null;
	}
}

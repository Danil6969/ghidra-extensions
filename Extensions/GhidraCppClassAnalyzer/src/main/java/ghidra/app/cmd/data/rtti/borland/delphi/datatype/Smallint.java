package ghidra.app.cmd.data.rtti.borland.delphi.datatype;

import ghidra.program.model.data.*;

public class Smallint {
	public static TypedefDataType getDataType(CategoryPath path, DataTypeManager manager) {
		ShortDataType dt = ShortDataType.dataType;
		return new TypedefDataType(path, "Smallint", dt, manager);
	}
}

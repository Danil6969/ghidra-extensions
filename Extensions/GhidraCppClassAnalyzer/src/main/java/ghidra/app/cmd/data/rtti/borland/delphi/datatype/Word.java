package ghidra.app.cmd.data.rtti.borland.delphi.datatype;

import ghidra.program.model.data.*;

public class Word {
	public static TypedefDataType getDataType(CategoryPath path, DataTypeManager manager) {
		WordDataType dt = WordDataType.dataType;
		return new TypedefDataType(path, "Word", dt, manager);
	}
}

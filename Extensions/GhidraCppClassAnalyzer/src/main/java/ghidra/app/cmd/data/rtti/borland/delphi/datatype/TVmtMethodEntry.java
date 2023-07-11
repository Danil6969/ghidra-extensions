package ghidra.app.cmd.data.rtti.borland.delphi.datatype;

import ghidra.program.model.data.*;

public class TVmtMethodEntry {
	public static StructureDataType getDataType(CategoryPath path, DataTypeManager manager) {
		StructureDataType dt = new StructureDataType(path, "TVmtMethodEntry", 0, manager);
		dt.add(Word.getDataType(path, manager), "Len", "");
		dt.add(CodePointer.getDataType(path, manager), "CodeAddress", "");
		dt.add(new ArrayDataType(CharDataType.dataType, 0, 1), "Name", "");
		return dt;
	}
}

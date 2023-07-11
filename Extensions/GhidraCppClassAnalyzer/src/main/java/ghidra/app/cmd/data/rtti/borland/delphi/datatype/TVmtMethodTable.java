package ghidra.app.cmd.data.rtti.borland.delphi.datatype;

import ghidra.program.model.data.*;

public class TVmtMethodTable {
	public static StructureDataType getDataType(CategoryPath path, DataTypeManager manager) {
		StructureDataType dt = new StructureDataType(path, "TVmtMethodTable", 0, manager);
		dt.add(Word.getDataType(path, manager), "Count", "");
		dt.add(new ArrayDataType(TVmtMethodEntry.getDataType(path, manager), 0, 6), "Entry", "");
		dt.add(Word.getDataType(path, manager), "ExCount", "");
		dt.add(new ArrayDataType(TVmtMethodExEntry.getDataType(path, manager), 0, 8), "ExEntry", "");
		return dt;
	}
}

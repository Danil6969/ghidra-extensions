package ghidra.app.cmd.data.rtti.borland.delphi.datatype;

import ghidra.program.model.data.*;

public class TVmtMethodTable_1 {
	public static StructureDataType getDataType(CategoryPath path, DataTypeManager manager) {
		StructureDataType dt = new StructureDataType(path, "TVmtMethodTable_1", 0, manager);
		StructureDataType entryDT = TVmtMethodExEntry.getDataType(path, manager);
		dt.add(Word.getDataType(path, manager), "ExCount", "");
		dt.add(new ArrayDataType(entryDT, 0, entryDT.getLength()), "ExEntry", "");
		return dt;
	}
}

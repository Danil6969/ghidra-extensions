package ghidra.app.cmd.data.rtti.borland.delphi.datatype;

import ghidra.program.model.data.*;

public class TVmtMethodTable_0 {
	public static StructureDataType getDataType(CategoryPath path, DataTypeManager manager) {
		StructureDataType dt = new StructureDataType(path, "TVmtMethodTable_0", 0, manager);
		StructureDataType entryDT = TVmtMethodEntry.getDataType(path, manager);
		dt.add(Word.getDataType(path, manager), "Count", "");
		dt.add(new ArrayDataType(entryDT, 0, entryDT.getLength()), "Entry", "");
		return dt;
	}
}

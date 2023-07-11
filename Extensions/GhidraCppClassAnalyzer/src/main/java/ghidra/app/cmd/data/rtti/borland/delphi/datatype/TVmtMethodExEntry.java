package ghidra.app.cmd.data.rtti.borland.delphi.datatype;

import ghidra.program.model.data.*;

public class TVmtMethodExEntry {
	public static StructureDataType getDataType(CategoryPath path, DataTypeManager manager) {
		StructureDataType dt = new StructureDataType(path, "TVmtMethodExEntry", 0, manager);
		dt.add(PVmtMethodEntry.getDataType(path, manager), "Entry", "");
		dt.add(Word.getDataType(path, manager), "Flags", "");
		dt.add(Smallint.getDataType(path, manager), "VirtualIndex", "");
		return dt;
	}
}

package ghidra.app.cmd.data.rtti.borland.delphi.datatype;

import ghidra.program.model.data.*;

public class PVmtMethodTable {
	public static TypedefDataType getDataType(CategoryPath path, DataTypeManager manager) {
		PointerDataType dt = new PointerDataType(TVmtMethodTable_0.getDataType(path, manager), manager);
		return new TypedefDataType(path, "PVmtMethodTable", dt, manager);
	}
}

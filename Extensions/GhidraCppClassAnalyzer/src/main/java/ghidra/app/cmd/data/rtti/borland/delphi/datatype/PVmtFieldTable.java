package ghidra.app.cmd.data.rtti.borland.delphi.datatype;

import ghidra.program.model.data.*;

public class PVmtFieldTable {
	public static TypedefDataType getDataType(CategoryPath path, DataTypeManager manager) {
		PointerDataType dt = new PointerDataType(TVmtFieldTable_0.getDataType(path, manager), manager);
		return new TypedefDataType(path, "PVmtFieldTable", dt, manager);
	}
}

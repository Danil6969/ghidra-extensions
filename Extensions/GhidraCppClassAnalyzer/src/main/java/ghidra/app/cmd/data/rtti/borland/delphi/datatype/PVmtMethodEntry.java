package ghidra.app.cmd.data.rtti.borland.delphi.datatype;

import ghidra.program.model.data.*;

public class PVmtMethodEntry {
	public static TypedefDataType getDataType(CategoryPath path, DataTypeManager manager) {
		PointerDataType dt = new PointerDataType(TVmtMethodEntry.getDataType(path, manager), manager);
		return new TypedefDataType(path, "PVmtMethodEntry", dt, manager);
	}
}

package ghidra.app.cmd.data.rtti.borland.delphi;

import ghidra.program.model.data.*;

public class TTypeKind {
	public static EnumDataType getDataType(CategoryPath path, DataTypeManager manager) {
		EnumDataType TTypeKindDT = new EnumDataType(path, "TTypeKind", 1, manager);
		TTypeKindDT.add("tkUnknown", 0);
		TTypeKindDT.add("tkInteger", 1);
		TTypeKindDT.add("tkChar", 2);
		TTypeKindDT.add("tkEnumeration", 3);
		TTypeKindDT.add("tkFloat", 4);
		TTypeKindDT.add("tkString", 5);
		TTypeKindDT.add("tkSet", 6);
		TTypeKindDT.add("tkClass", 7);
		TTypeKindDT.add("tkMethod", 8);
		TTypeKindDT.add("tkWChar", 9);
		TTypeKindDT.add("tkLString", 10);
		TTypeKindDT.add("tkWString", 11);
		TTypeKindDT.add("tkVariant", 12);
		TTypeKindDT.add("tkArray", 13);
		TTypeKindDT.add("tkRecord", 14);
		TTypeKindDT.add("tkInterface", 15);
		TTypeKindDT.add("tkInt64", 16);
		TTypeKindDT.add("tkDynArray", 17);
		TTypeKindDT.add("tkUString", 18);
		TTypeKindDT.add("tkClassRef", 19);
		TTypeKindDT.add("tkPointer", 20);
		TTypeKindDT.add("tkProcedure", 21);
		TTypeKindDT.add("tkMRecord", 22);
		return TTypeKindDT;
	}
}

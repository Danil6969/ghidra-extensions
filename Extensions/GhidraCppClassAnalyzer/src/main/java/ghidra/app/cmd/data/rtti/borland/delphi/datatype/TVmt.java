package ghidra.app.cmd.data.rtti.borland.delphi.datatype;

import ghidra.app.cmd.data.rtti.borland.delphi.util.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.Relocation;

import java.util.List;

public class TVmt {
	public static StructureDataType getDataType(long maxLength, CategoryPath path, DataTypeManager manager) {
		TypedefDataType SizeIntDT = SizeInt.getDataType(path, manager);
		if (SizeIntDT == null) return null;
		PointerDataType pointerDT = PointerDataType.dataType;
		int pointerSize = pointerDT.getLength();
		StructureDataType dt = new StructureDataType(path, "TVmt", 0, manager);
		dt.add(pointerDT, "SelfPtr", "Pointer to self");
		dt.add(pointerDT, "IntfTable", "Pointer to interface table");
		dt.add(pointerDT, "AutoTable", "Pointer to automation initialization");
		dt.add(pointerDT, "InitTable", "Pointer to object initialization");
		dt.add(PTypeInfo.getDataType(path, manager), "TypeInfo", "Pointer to type information table");
		dt.add(PVmtFieldTable.getDataType(path, manager), "FieldTable", "Pointer to field definition table");
		dt.add(PVmtMethodTable.getDataType(path, manager), "MethodTable", "Pointer to method definition table");
		dt.add(pointerDT, "DynamicTable", "Pointer to dynamic method table");
		dt.add(PShortString.getDataType(path, manager), "ClassName", "Class name pointer");
		dt.add(SizeIntDT, "InstanceSize", "Instance size");
		dt.add(pointerDT, "Parent", "Pointer to parent class");
		while (dt.getLength() < maxLength - (maxLength % pointerSize)) {
			dt.add(pointerDT);
		}
		while (dt.getLength() < maxLength) {
			dt.add(Undefined.getUndefinedDataType(1));
		}
		return dt;
	}

	public static void putObject(Address address, long maxLength, CategoryPath path, Program program) {
		ProgramBasedDataTypeManager manager = program.getDataTypeManager();
		StructureDataType TVmtDT = TVmt.getDataType(maxLength, path, manager);
		PointerDataType pointerDT = PointerDataType.dataType;
		PascalString255DataType stringDT = PascalString255DataType.dataType;
		ListingUtils.deleteCreateData(address, TVmtDT, program);
		address = address.add(pointerDT.getLength());
		address = address.add(pointerDT.getLength());
		address = address.add(pointerDT.getLength());
		address = address.add(pointerDT.getLength());
		Address vmtTypeInfo = MemoryUtil.readPointer(address, program);
		if (vmtTypeInfo != null) {
			TTypeInfo.putObject(vmtTypeInfo, path, program);
		}
		address = address.add(pointerDT.getLength());
		Address vmtFieldTable = MemoryUtil.readPointer(address, program);
		if (vmtFieldTable != null) {
			TVmtFieldTable_0.putObject(vmtFieldTable, path, program);
		}
		address = address.add(pointerDT.getLength());
		address = address.add(pointerDT.getLength());
		address = address.add(pointerDT.getLength());
		Address vmtClassName = MemoryUtil.readPointer(address, program);
		if (vmtClassName != null) {
			ListingUtils.deleteCreateData(vmtClassName, stringDT, program);
		}
	}

	public static boolean isValid(Address address, long maxLength, List<Relocation> relocations, Program program) {
		try {
			int pointerSize = PointerDataType.dataType.getLength();
			for (int i = 0; i < 9; i++) {
				if (!MemoryUtil.containsValidPointer(address.add(pointerSize * i), relocations, program)) {
					return false;
				}
			}
			Address nextaddress = address.add(pointerSize * 10);
			nextaddress = nextaddress.add(4);
			while (nextaddress.getOffset() < address.add(maxLength).getOffset()) {
				if (!MemoryUtil.containsValidPointer(nextaddress, relocations, program)) {
					return false;
				}
				nextaddress = nextaddress.add(pointerSize);
			}
			nextaddress = address.add(pointerSize * 4);
			nextaddress = MemoryUtil.readPointer(nextaddress, program);
			long kind = MemoryUtil.readNumber(nextaddress, 1, program);
			if (kind < 0 || kind > 22 ) {
				return false;
			}
			nextaddress = nextaddress.add(1);
			String str1 = MemoryUtil.readPascalString(nextaddress, program);
			if (str1 == null) {
				return false;
			}
			nextaddress = address.add(pointerSize * 8);
			nextaddress = MemoryUtil.readPointer(nextaddress, program);
			String str2 = MemoryUtil.readPascalString(nextaddress, program);
			return str1.equals(str2);
		} catch (MemoryAccessException e) {
			return false; // Shouldn't hit exception during parsing
		}
	}

	public static String getVMTTypeName(Address address, Program program) {
		if (address == null) return null;
		Memory memory = program.getMemory();
		Address fieldaddress = address.add(PointerDataType.dataType.getLength() * 8);
		Address stringaddress = MemoryUtil.readPointer(fieldaddress, program);
		if (stringaddress == null) return null;
		return MemoryUtil.readPascalString(stringaddress, program);
	}
}

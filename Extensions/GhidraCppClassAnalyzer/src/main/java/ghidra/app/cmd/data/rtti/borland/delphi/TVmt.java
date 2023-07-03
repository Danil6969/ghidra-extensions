package ghidra.app.cmd.data.rtti.borland.delphi;

import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation;

import java.util.List;

public class TVmt {
	public static StructureDataType getDataType(CategoryPath path, DataTypeManager manager, long maxLength) {
		PointerDataType pointerDT = PointerDataType.dataType;
		int pointerSize = pointerDT.getLength();
		StructureDataType VirtualMethodTableDT = new StructureDataType(path, "TVmt", 0, manager);
		VirtualMethodTableDT.add(pointerDT, "SelfPtr", "Pointer to self");
		VirtualMethodTableDT.add(pointerDT, "IntfTable", "Pointer to interface table");
		VirtualMethodTableDT.add(pointerDT, "AutoTable", "Pointer to automation initialization");
		VirtualMethodTableDT.add(pointerDT, "InitTable", "Pointer to object initialization");
		VirtualMethodTableDT.add(new PointerDataType(TTypeInfo.getDataType(path, manager)), "TypeInfo", "Pointer to type information table");
		VirtualMethodTableDT.add(pointerDT, "FieldTable", "Pointer to field definition table");
		VirtualMethodTableDT.add(pointerDT, "MethodTable", "Pointer to method definition table");
		VirtualMethodTableDT.add(pointerDT, "DynamicTable", "Pointer to dynamic method table");
		VirtualMethodTableDT.add(new PointerDataType(PascalString255DataType.dataType), "ClassName", "Class name pointer");
		VirtualMethodTableDT.add(AbstractIntegerDataType.getSignedDataType(pointerSize, manager), "InstanceSize", "Instance size");
		VirtualMethodTableDT.add(pointerDT, "Parent", "Pointer to parent class");
		while (VirtualMethodTableDT.getLength() < maxLength - (maxLength % pointerSize)) {
			VirtualMethodTableDT.add(pointerDT);
		}
		while (VirtualMethodTableDT.getLength() < maxLength) {
			VirtualMethodTableDT.add(Undefined.getUndefinedDataType(1));
		}
		return VirtualMethodTableDT;
	}

	public static boolean isValid(Address address, List<Relocation> relocations, Program program) {
		try {
			int pointerSize = PointerDataType.dataType.getLength();
			for (int i = 0; i < 9; i++) {
				if (!containsValidPointer(address.add(pointerSize * i), relocations, program)) {
					return false;
				}
			}
			Address nextaddress = address.add(pointerSize * 10);
			nextaddress = nextaddress.add(4);
			if (!containsValidPointer(nextaddress, relocations, program)) {
				return false;
			}
			nextaddress = address.add(pointerSize * 4);
			nextaddress = readPointer(nextaddress, program);
			long kind = readNumber(nextaddress, 1, program);
			if (kind > 22) return false;
			if (kind < 0) return false;
			nextaddress = nextaddress.add(1);
			String str1 = readString(nextaddress, program);
			if (str1 == null) {
				return false;
			}
			nextaddress = address.add(pointerSize * 8);
			nextaddress = readPointer(nextaddress, program);
			String str2 = readString(nextaddress, program);
			if (str2 == null) {
				return false;
			}
			if (!str1.equals(str2)) {
				return false;
			}
			return true;
		} catch (MemoryAccessException e) {
			return false;
		}
	}

	public static String getVMTTypeName(Address address, Program program) {
		if (address == null) return null;
		Memory memory = program.getMemory();
		Address fieldaddress = address.add(PointerDataType.dataType.getLength() * 8);
		Address stringaddress = readPointer(fieldaddress, program);
		if (stringaddress == null) return null;
		return readString(stringaddress, program);
	}

	private static String readString(Address address, Program program) {
		if (address == null) return null;
		try {
			long length = readNumber(address, 1, program);
			StringBuilder str = new StringBuilder();
			for (int i = 1; i < length + 1; i++) {
				char c = (char) readNumber(address.add(i), 1, program);
				str.append(c);
			}
			return str.toString();
		} catch (MemoryAccessException e) {
			return null;
		} catch (NullPointerException e) {
			return null;
		}
	}

	private static byte[] readBytes(Address address, int size, Program program) throws MemoryAccessException {
		Memory memory = program.getMemory();
		byte[] bytes = new byte[size];
		memory.getBytes(address, bytes);
		return bytes;
	}

	private static long readNumber(Address address, int size, Program program) throws MemoryAccessException {
		boolean bigEndian = program.getLanguage().isBigEndian();
		byte[] bytes = readBytes(address, size, program);
		return Utils.bytesToLong(bytes, size, bigEndian);
	}

	private static Address readPointer(Address address, Program program) {
		if (address == null) return null;
		int size = address.getPointerSize();
		try {
			long offset = readNumber(address, size, program);
			if (offset == 0) return null; // Assume null pointer is not mapped to any valid data
			AddressSpace space = address.getAddressSpace();
			return space.getAddress(offset); // Assume address space is the same
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			return null;
		}
	}

	private static boolean containsValidPointer(Address address, List<Relocation> relocations, Program program) {
		try {
			long num = readNumber(address, PointerDataType.dataType.getLength(), program);
			if (num == 0) return true; // null pointer is valid
			for (Relocation relocation : relocations) {
				if (relocation.getAddress().equals(address)) return true;
			}
		} catch (MemoryAccessException e) {
			return false;
		}
		return false;
	}
}

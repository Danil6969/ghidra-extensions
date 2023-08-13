package ghidra.app.cmd.data.rtti.borland.delphi.util;

import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.*;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.Relocation;

import java.util.List;

public class MemoryUtil {
	public static boolean containsValidPointer(Address address, List<Relocation> relocations, Program program) {
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

	// Reads C string
	public static String readCString(Address address, Program program) {
		if (address == null) return null;
		try {
			StringBuilder str = new StringBuilder();
			while (MemoryUtil.readNumber(address, 1, program) != 0) {
				char c = (char) MemoryUtil.readNumber(address, 1, program);
				address = address.add(1);
				str.append(c);
			}
			return str.toString();
		} catch (MemoryAccessException | NullPointerException e) {
			return null;
		}
	}

	// Reads Pascal string
	public static String readPascalString(Address address, Program program) {
		if (address == null) return null;
		try {
			long length = MemoryUtil.readNumber(address, 1, program);
			StringBuilder str = new StringBuilder();
			for (int i = 1; i < length + 1; i++) {
				char c = (char) MemoryUtil.readNumber(address.add(i), 1, program);
				str.append(c);
			}
			return str.toString();
		} catch (MemoryAccessException | NullPointerException e) {
			return null;
		}
	}

	public static Address readPointer(Address address, Program program) {
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

	public static long readNumber(Address address, int size, Program program) throws MemoryAccessException {
		boolean bigEndian = program.getLanguage().isBigEndian();
		byte[] bytes = readBytes(address, size, program);
		return Utils.bytesToLong(bytes, size, bigEndian);
	}

	public static byte[] readBytes(Address address, int size, Program program) throws MemoryAccessException {
		Memory memory = program.getMemory();
		byte[] bytes = new byte[size];
		memory.getBytes(address, bytes);
		return bytes;
	}
}

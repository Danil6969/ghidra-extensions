package ghidra.program.emulation.relocation;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.pe.*;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.pcode.exec.PcodeExecutorStatePiece;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.trace.model.modules.TraceModule;

import java.io.IOException;

public class PeRelocator extends DynamicRelocator {

	private final static int LDRP_RELOCATION_FINAL = 0x2;

	public PeRelocator(Program program, TraceModule module, PcodeExecutorState<byte[]> state) {
		super(program, module, state);
	}

	@Override
	public void relocateAll()
			throws MemoryAccessException {
		if (diff == 0) return;
		BaseRelocation[] relocs = getBaseRelocationDataDirectory().getBaseRelocations();
		for (BaseRelocation reloc : relocs) {
			long virtualAddress = reloc.getVirtualAddress();
			int nextOffset = 0;
			while (nextOffset < reloc.getCount()) {
				int type = reloc.getType(nextOffset);
				long offset = reloc.getOffset(nextOffset);
				long fixupVA = virtualAddress + offset;
				Address dynamicAddr = dynamicBase.add(fixupVA);
				Address staticAddr = staticBase.add(fixupVA);
				int ptrSize = getByteLength(type);
				if (ptrSize == 0) {
					nextOffset++;
					continue;
				}
				byte[] bytes = readBytes(dynamicAddr, ptrSize);
				switch (type) {
					case BaseRelocation.IMAGE_REL_BASED_HIGHLOW: {
						int oldValue = (int) Utils.bytesToLong(bytes, ptrSize, isBigEndian);
						int newValue = oldValue + (int) diff;
						writeBytes(dynamicAddr, ptrSize, Utils.longToBytes(newValue, ptrSize, isBigEndian));
						break;
					}
					case BaseRelocation.IMAGE_REL_BASED_HIGH: {
						int oldValue = (int) Utils.bytesToLong(bytes, ptrSize, isBigEndian);
						int temp = oldValue << 16;
						temp += (int) diff;
						short newValue = (short) (temp >> 16);
						writeBytes(dynamicAddr, ptrSize, Utils.longToBytes(newValue, ptrSize, isBigEndian));
						break;
					}
					case BaseRelocation.IMAGE_REL_BASED_HIGHADJ: {
						// If the address has already been relocated then don't
						// process it again now or information will be lost.
						if ((offset & LDRP_RELOCATION_FINAL) != 0) {
							// Must adjust nextOffset though
							nextOffset++;
							break;
						}
						int oldValue = (int) Utils.bytesToLong(bytes, ptrSize, isBigEndian);
						int temp = oldValue << 16;
						nextOffset++;
						int nextWord = (reloc.getType(nextOffset) & 0xf) << 12 | (reloc.getOffset(nextOffset) & 0xfff);
						temp += nextWord;
						temp += diff;
						temp += 0x8000;
						short newValue = (short) (temp >> 16);
						writeBytes(dynamicAddr, ptrSize, Utils.longToBytes(newValue, ptrSize, isBigEndian));
						break;
					}
					case BaseRelocation.IMAGE_REL_BASED_HIGH3ADJ: {
						long oldValue = Utils.bytesToLong(bytes, ptrSize, isBigEndian);
						long temp = oldValue << 16;
						nextOffset++;
						temp += (reloc.getType(nextOffset+1) & 0xf) << 12 | (reloc.getOffset(nextOffset+1) & 0xfff);
						temp <<= 16;
						temp += (reloc.getType(nextOffset) & 0xf) << 12 | (reloc.getOffset(nextOffset) & 0xfff);
						temp += diff;
						temp += 0x8000;
						temp >>= 16;
						temp += 0x8000;
						short newValue = (short) (temp >> 16);
						writeBytes(dynamicAddr, ptrSize, Utils.longToBytes(newValue, ptrSize, isBigEndian));
						nextOffset++;
						break;
					}
				}
				nextOffset++;
			}
		}
	}

	@Override
	public int getByteLength(int type) {
		switch (type) {
			case BaseRelocation.IMAGE_REL_BASED_HIGH:
			case BaseRelocation.IMAGE_REL_BASED_LOW:
			case BaseRelocation.IMAGE_REL_BASED_HIGHADJ:
			case BaseRelocation.IMAGE_REL_BASED_HIGH3ADJ:
				return 2;
			case BaseRelocation.IMAGE_REL_BASED_HIGHLOW:
			case BaseRelocation.IMAGE_REL_BASED_MIPS_JMPADDR:
				return 4;
			case BaseRelocation.IMAGE_REL_BASED_DIR64:
				return 8;
			case BaseRelocation.IMAGE_REL_BASED_ABSOLUTE:
			case BaseRelocation.IMAGE_REL_BASED_SECTION:
			case BaseRelocation.IMAGE_REL_BASED_REL32:
			case BaseRelocation.IMAGE_REL_BASED_IA64_IMM64:
			default:
				return 0;
		}
	}

	private BaseRelocationDataDirectory getBaseRelocationDataDirectory() {
		try {
			ByteProvider provider =
					new MemoryByteProvider(program.getMemory(), staticBase);
			PortableExecutable pe = new PortableExecutable(provider, PortableExecutable.SectionLayout.MEMORY);
			NTHeader nt = pe.getNTHeader();
			OptionalHeader oh = nt.getOptionalHeader();
			DataDirectory[] datadirs = oh.getDataDirectories();
			DataDirectory brdd = datadirs[OptionalHeader.IMAGE_DIRECTORY_ENTRY_BASERELOC];
			if (!(brdd instanceof BaseRelocationDataDirectory)) return null;
			return (BaseRelocationDataDirectory) brdd;
		} catch (IOException e) {
			return null;
		}
	}

	private long EXT_IMM64(long value, Address address, int size, int instPos, int valPos) throws MemoryAccessException {
		byte[] bytes = readBytes(address, 4);
		int input = (int) Utils.bytesToLong(bytes, 4, isBigEndian);
		long res = (((long) ((input >> instPos) & (((long) 1 << size) - 1))) << valPos);
		return value | res;
	}

	private void INS_IMM64(long value, Address address, int size, int instPos, int valPos) throws MemoryAccessException {
		byte[] bytes = readBytes(address, 4);
		int input = (int) Utils.bytesToLong(bytes, 4, isBigEndian);
		int temp1 = (input & ~(((1 << size) - 1) << instPos));
		int temp2 = ((int) ((((long) value >> valPos) & (((long) 1 << size) - 1))) << instPos);
		int res = temp1 | temp2;
		writeBytes(address, 4, Utils.longToBytes(res, 4, isBigEndian));
	}
}

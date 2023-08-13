/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.program.emulation.relocation;

import ghidra.app.util.bin.format.pe.OptionalHeader;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.modules.TraceModule;

import static ghidra.app.util.bin.format.pe.BaseRelocation.*;
import static ghidra.program.emulation.relocation.PeRelocationConstants.*;

public class PeRelocator extends DynamicRelocator {

	public PeRelocator(Program program, TraceModule module, PcodeExecutorState<byte[]> state) {
		super(program, module, state);
	}

	@Override
	public void relocateAll() {
		if (diff == 0) {
			return; // No relocation required, already at preferred address
		}
		long relocSize = getRelocSectionSize();
		if (relocSize == 0) {
			return; // Couldn't parse headers and fetch relocation size
		}
		Address start = program.getMemory().getBlock(".reloc").getStart().add(diff);
		Address blockAddress = start;
		while (blockAddress.getOffset() < start.add(relocSize).getOffset()) {
			long virtualAddress = readNumber(blockAddress, 4);
			long blockSize = readNumber(blockAddress.add(4), 4);
			Address nextOffset = blockAddress.add(8);
			Address endAddress = blockAddress.add(blockSize);
			while (nextOffset.getOffset() < endAddress.getOffset()) {
				short word = (short) readNumber(nextOffset, 2);
				int type = (word >> 12) & 0xf;
				int ptrSize = getByteLength(type);
				if (ptrSize == 0) {
					nextOffset = nextOffset.add(2);
					continue;
				}
				short offset = (short) (word & 0xfff);
				long fixupVA = virtualAddress + offset;
				Address dynamicAddr = dynamicBase.add(fixupVA);
				nextOffset = nextOffset.add(2);
				long input = readNumber(dynamicAddr, ptrSize);
				switch (type) {
					case IMAGE_REL_BASED_HIGHLOW: {
						writeNumber(dynamicAddr, ptrSize, (int) input + diff);
						break;
					}
					case IMAGE_REL_BASED_HIGH: {
						int temp = (int) input << 16;
						temp += (int) diff;
						writeNumber(dynamicAddr, ptrSize, (short) (temp >> 16));
						break;
					}
					case IMAGE_REL_BASED_HIGHADJ: {
						// Must adjust nextOffset first
						nextOffset = nextOffset.add(2);
						// If the address has already been relocated then don't
						// process it again now or information will be lost.
						if ((offset & LDRP_RELOCATION_FINAL) != 0) {
							break;
						}
						int temp = (int) input << 16;
						word = (short) readNumber(nextOffset, 2);
						temp += word;
						temp += diff;
						temp += 0x8000;
						writeNumber(dynamicAddr, ptrSize, (short) (temp >> 16));
						break;
					}
					case IMAGE_REL_BASED_LOW: {
						writeNumber(dynamicAddr, ptrSize, input + diff);
						break;
					}
					case IMAGE_REL_BASED_IA64_IMM64: {
						long aligned = dynamicAddr.getOffset() & ~0xf;
						dynamicAddr = dynamicAddr.getAddressSpace().getAddress(aligned);
						long value64 = 0;

						value64 = EXT_IMM64(value64,
								dynamicAddr.add(EMARCH_ENC_I17_IMM7B_INST_WORD_X*ptrSize),
								EMARCH_ENC_I17_IMM7B_SIZE_X,
								EMARCH_ENC_I17_IMM7B_INST_WORD_POS_X,
								EMARCH_ENC_I17_IMM7B_VAL_POS_X);
						value64 = EXT_IMM64(value64,
								dynamicAddr.add(EMARCH_ENC_I17_IMM9D_INST_WORD_X*ptrSize),
								EMARCH_ENC_I17_IMM9D_SIZE_X,
								EMARCH_ENC_I17_IMM9D_INST_WORD_POS_X,
								EMARCH_ENC_I17_IMM9D_VAL_POS_X);
						value64 = EXT_IMM64(value64,
								dynamicAddr.add(EMARCH_ENC_I17_IMM5C_INST_WORD_X*ptrSize),
								EMARCH_ENC_I17_IMM5C_SIZE_X,
								EMARCH_ENC_I17_IMM5C_INST_WORD_POS_X,
								EMARCH_ENC_I17_IMM5C_VAL_POS_X);
						value64 = EXT_IMM64(value64,
								dynamicAddr.add(EMARCH_ENC_I17_IC_INST_WORD_X*ptrSize),
								EMARCH_ENC_I17_IC_SIZE_X,
								EMARCH_ENC_I17_IC_INST_WORD_POS_X,
								EMARCH_ENC_I17_IC_VAL_POS_X);
						value64 = EXT_IMM64(value64,
								dynamicAddr.add(EMARCH_ENC_I17_IMM41a_INST_WORD_X*ptrSize),
								EMARCH_ENC_I17_IMM41a_SIZE_X,
								EMARCH_ENC_I17_IMM41a_INST_WORD_POS_X,
								EMARCH_ENC_I17_IMM41a_VAL_POS_X);
						value64 = EXT_IMM64(value64,
								dynamicAddr.add(EMARCH_ENC_I17_IMM41b_INST_WORD_X*ptrSize),
								EMARCH_ENC_I17_IMM41b_SIZE_X,
								EMARCH_ENC_I17_IMM41b_INST_WORD_POS_X,
								EMARCH_ENC_I17_IMM41b_VAL_POS_X);
						value64 = EXT_IMM64(value64,
								dynamicAddr.add(EMARCH_ENC_I17_IMM41c_INST_WORD_X*ptrSize),
								EMARCH_ENC_I17_IMM41c_SIZE_X,
								EMARCH_ENC_I17_IMM41c_INST_WORD_POS_X,
								EMARCH_ENC_I17_IMM41c_VAL_POS_X);
						value64 = EXT_IMM64(value64,
								dynamicAddr.add(EMARCH_ENC_I17_SIGN_INST_WORD_X*ptrSize),
								EMARCH_ENC_I17_SIGN_SIZE_X,
								EMARCH_ENC_I17_SIGN_INST_WORD_POS_X,
								EMARCH_ENC_I17_SIGN_VAL_POS_X);

						value64 += diff;

						INS_IMM64(value64,
								dynamicAddr.add(EMARCH_ENC_I17_IMM7B_INST_WORD_X*ptrSize),
								EMARCH_ENC_I17_IMM7B_SIZE_X,
								EMARCH_ENC_I17_IMM7B_INST_WORD_POS_X,
								EMARCH_ENC_I17_IMM7B_VAL_POS_X);
						INS_IMM64(value64,
								dynamicAddr.add(EMARCH_ENC_I17_IMM9D_INST_WORD_X*ptrSize),
								EMARCH_ENC_I17_IMM9D_SIZE_X,
								EMARCH_ENC_I17_IMM9D_INST_WORD_POS_X,
								EMARCH_ENC_I17_IMM9D_VAL_POS_X);
						INS_IMM64(value64,
								dynamicAddr.add(EMARCH_ENC_I17_IMM5C_INST_WORD_X*ptrSize),
								EMARCH_ENC_I17_IMM5C_SIZE_X,
								EMARCH_ENC_I17_IMM5C_INST_WORD_POS_X,
								EMARCH_ENC_I17_IMM5C_VAL_POS_X);
						INS_IMM64(value64,
								dynamicAddr.add(EMARCH_ENC_I17_IC_INST_WORD_X*ptrSize),
								EMARCH_ENC_I17_IC_SIZE_X,
								EMARCH_ENC_I17_IC_INST_WORD_POS_X,
								EMARCH_ENC_I17_IC_VAL_POS_X);
						INS_IMM64(value64,
								dynamicAddr.add(EMARCH_ENC_I17_IMM41a_INST_WORD_X*ptrSize),
								EMARCH_ENC_I17_IMM41a_SIZE_X,
								EMARCH_ENC_I17_IMM41a_INST_WORD_POS_X,
								EMARCH_ENC_I17_IMM41a_VAL_POS_X);
						INS_IMM64(value64,
								dynamicAddr.add(EMARCH_ENC_I17_IMM41b_INST_WORD_X*ptrSize),
								EMARCH_ENC_I17_IMM41b_SIZE_X,
								EMARCH_ENC_I17_IMM41b_INST_WORD_POS_X,
								EMARCH_ENC_I17_IMM41b_VAL_POS_X);
						INS_IMM64(value64,
								dynamicAddr.add(EMARCH_ENC_I17_IMM41c_INST_WORD_X*ptrSize),
								EMARCH_ENC_I17_IMM41c_SIZE_X,
								EMARCH_ENC_I17_IMM41c_INST_WORD_POS_X,
								EMARCH_ENC_I17_IMM41c_VAL_POS_X);
						INS_IMM64(value64,
								dynamicAddr.add(EMARCH_ENC_I17_SIGN_INST_WORD_X*ptrSize),
								EMARCH_ENC_I17_SIGN_SIZE_X,
								EMARCH_ENC_I17_SIGN_INST_WORD_POS_X,
								EMARCH_ENC_I17_SIGN_VAL_POS_X);
						break;
					}
					case IMAGE_REL_BASED_DIR64: {
						writeNumber(dynamicAddr, ptrSize, input + diff);
						break;
					}
					case IMAGE_REL_BASED_MIPS_JMPADDR : {
						int temp = ((int) input & 0x3ffffff) << 2;
						temp += diff;
						temp = ((int) input & ~0x3ffffff) | ((temp >> 2) & 0x3ffffff);
						writeNumber(dynamicAddr, ptrSize, temp);
						break;
					}
					case IMAGE_REL_BASED_HIGH3ADJ: {
						long temp = input << 16;
						nextOffset = nextOffset.add(2);
						temp += (short) readNumber(nextOffset.add(1), 2);
						temp <<= 16;
						temp += (short) readNumber(nextOffset, 2);
						temp += diff;
						temp += 0x8000;
						temp >>= 16;
						temp += 0x8000;
						writeNumber(dynamicAddr, ptrSize, (short) (temp >> 16));
						nextOffset = nextOffset.add(2);
						break;
					}
				}
			}
			blockAddress = endAddress;
		}
	}

	@Override
	public int getByteLength(int type) {
		switch (type) {
			case IMAGE_REL_BASED_HIGH:
			case IMAGE_REL_BASED_LOW:
			case IMAGE_REL_BASED_HIGHADJ:
			case IMAGE_REL_BASED_HIGH3ADJ:
				return 2;
			case IMAGE_REL_BASED_HIGHLOW:
			case IMAGE_REL_BASED_MIPS_JMPADDR:
				return 4;
			case IMAGE_REL_BASED_DIR64:
				return 8;
			case IMAGE_REL_BASED_ABSOLUTE:
			case IMAGE_REL_BASED_SECTION:
			case IMAGE_REL_BASED_REL32:
			case IMAGE_REL_BASED_IA64_IMM64:
			default:
				return 0;
		}
	}

	private long getRelocSectionSize() {
		Listing listing = program.getListing();
		Address address = staticBase; // Points to DOS header
		int offset = listing.getDataAt(address).getLength();
		address = address.add(offset); // Points to NT Headers
		DataType dataType = listing.getDataAt(address).getDataType();
		if (!(dataType instanceof Structure)) {
			return 0;
		}
		Structure ntHeadersDT = (Structure) dataType;
		DataTypeComponent optionalHeaderComponent = ntHeadersDT.getComponent(2);
		offset = optionalHeaderComponent.getOffset();
		address = address.add(offset); // Points to optional header
		dataType = optionalHeaderComponent.getDataType();
		if (!(dataType instanceof Structure)) {
			return 0;
		}
		Structure optionalHeaderDT = (Structure) dataType;
		int numComponents = optionalHeaderDT.getNumComponents();
		DataTypeComponent dataDirectoryComponent = optionalHeaderDT.getComponent(numComponents - 1);
		offset = dataDirectoryComponent.getOffset();
		address = address.add(offset); // Points to data directories array
		dataType = dataDirectoryComponent.getDataType();
		if (!(dataType instanceof Array)) {
			return 0;
		}
		Array dataDirectoriesDT = (Array) dataType;
		offset = dataDirectoriesDT.getElementLength() * OptionalHeader.IMAGE_DIRECTORY_ENTRY_BASERELOC;
		address = address.add(offset); // Points to data directory for base reloc
		dataType = dataDirectoriesDT.getDataType();
		if (!(dataType instanceof Structure)) {
			return 0;
		}
		Structure dataDirectoryDT = (Structure) dataType;
		Address relocAddress = staticBase.add(readNumber(address.add(diff), dataDirectoryDT.getComponent(0).getLength()));
		if (!program.getMemory().getBlock(relocAddress).getName().equals(".reloc")) {
			return 0;
		}
		offset = dataDirectoryDT.getComponent(1).getOffset();
		address = address.add(offset);
		return readNumber(address.add(diff), dataDirectoryDT.getComponent(1).getLength());
	}

	private long EXT_IMM64(long value, Address address, int size, int instPos, int valPos) {
		int input = (int) readNumber(address, 4);
		long res = (((long) ((input >> instPos) & (((long) 1 << size) - 1))) << valPos);
		return value | res;
	}

	private void INS_IMM64(long value, Address address, int size, int instPos, int valPos) {
		int input = (int) readNumber(address, 4);
		int temp1 = (input & ~(((1 << size) - 1) << instPos));
		int temp2 = ((int) ((((long) value >> valPos) & (((long) 1 << size) - 1))) << instPos);
		writeNumber(address, 4, temp1 | temp2);
	}
}

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

import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.pcode.exec.PcodeExecutorStatePiece;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.trace.model.modules.TraceModule;

public abstract class DynamicRelocator {
	protected Program program;
	protected TraceModule module;
	protected Address staticBase;
	protected Address dynamicBase;
	protected long diff;
	protected Language language;
	protected Memory memory;
	protected boolean bigEndian;
	protected PcodeExecutorState<byte[]> state;

	public DynamicRelocator(Program program, TraceModule module, PcodeExecutorState<byte[]> state) {
		this.program = program;
		this.module = module;
		this.state = state;
	}

	public void init() {
		staticBase = program.getImageBase();
		dynamicBase = module.getBase();
		diff = dynamicBase.getOffset() - staticBase.getOffset();
		language = state.getLanguage();
		bigEndian = language.isBigEndian();
		memory = program.getMemory();
	}

	public abstract void relocateAll();
	public abstract int getByteLength(int type);

	protected long readNumber(Address address, int size) {
		byte[] bytes = readBytes(address, size);
		return Utils.bytesToLong(bytes, size, bigEndian);
	}

	protected void writeNumber(Address address, int size, long num) {
		byte[] bytes = Utils.longToBytes(num, size, bigEndian);
		writeBytes(address, size, bytes);
	}

	protected byte[] readBytes(Address address, int size) {
		return state.getVar(address, size, false, PcodeExecutorStatePiece.Reason.INSPECT);
	}

	protected void writeBytes(Address address, int size, byte[] buf) {
		state.setVar(address, size, false, buf);
	}
}

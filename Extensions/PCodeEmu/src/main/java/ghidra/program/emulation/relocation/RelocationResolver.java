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
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.trace.model.modules.TraceModule;

public class RelocationResolver {

	public static void relocateAll(Program program, TraceModule module, PcodeExecutorState<byte[]> state) throws MemoryAccessException {
		DynamicRelocator relocator = getRelocator(program.getExecutableFormat(), program, module, state);
		relocator.relocateAll();
	}

	private static DynamicRelocator getRelocator(String executableFormat, Program program,
												 TraceModule module, PcodeExecutorState<byte[]> state) {
		DynamicRelocator res = null;
		switch (executableFormat) {
			case "Portable Executable (PE)" :
				res = new PeRelocator(program, module, state);
		}
		if (res != null) {
			res.init();
		}
		return res;
	}
}

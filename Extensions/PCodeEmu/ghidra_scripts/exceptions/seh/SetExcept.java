package exceptions.seh;/* ###
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
//@category Exceptions

import ghidra.pcode.utils.PcodeUtils;
import ghidra.app.plugin.core.clear.ClearCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.ProgramContext;

import java.math.BigInteger;

public class SetExcept extends GhidraScript {
	@Override
	protected void run() throws Exception {
		ProgramContext context = currentProgram.getProgramContext();
		Register reg1 = context.getRegister("exceptFlag");
		Register reg2 = context.getRegister("exceptOffset");
		Register reg3 = context.getRegister("exceptVariant");
		if (reg1 == null || reg2 == null) return;
		Listing lst = currentProgram.getListing();
		if (currentSelection == null) {
			if (currentAddress != null) {
				BigInteger val1 = BigInteger.valueOf(0);
				BigInteger val2 = BigInteger.valueOf(0);

				PcodeUtils.setContextRegister(currentProgram, monitor, reg1, val1, currentAddress);
				PcodeUtils.setContextRegister(currentProgram, monitor, reg2, val2, currentAddress);
			}
		}
		else {
			Address start = currentSelection.getMinAddress();
			long length = lst.getCodeUnitAt(start).getLength();

			Address end = currentSelection.getMaxAddress();
			long offset = end.getOffset() - start.getOffset() - length + 1;

			BigInteger val1 = BigInteger.valueOf(1);
			BigInteger val2 = BigInteger.valueOf(offset);

			PcodeUtils.setContextRegister(currentProgram, monitor, reg1, val1, start);
			PcodeUtils.setContextRegister(currentProgram, monitor, reg2, val2, start);

			String str = PcodeUtils.getDecompiledC(currentProgram, start, monitor);
			if (str == null) {
				return;
			}
			if (!str.contains("!catch(")) {
				return;
			}

			BigInteger val3 = BigInteger.valueOf(1);

			PcodeUtils.setContextRegister(currentProgram, monitor, reg1, val1, start);
			PcodeUtils.setContextRegister(currentProgram, monitor, reg2, val2, start);
			PcodeUtils.setContextRegister(currentProgram, monitor, reg3, val3, start);
		}
	}

	private void setExceptionFlags() {
		;
	}
}

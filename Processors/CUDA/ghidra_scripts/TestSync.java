/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.app.plugin.core.clear.ClearCmd;
import ghidra.app.plugin.core.clear.ClearFlowAndRepairCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.ProgramContext;

import java.math.BigInteger;

public class TestSync extends GhidraScript {

	@Override
	public void run() throws Exception {
		Listing lst = currentProgram.getListing();
		Address addr = currentAddress;
		Instruction instr = lst.getInstructionAt(addr);
		if (instr.getMnemonicString().equals("SSY")) {
			addr = getAddressFactory().getAddress(instr.getOpObjects(0)[0].toString());
			ProgramContext con = currentProgram.getProgramContext();
			Register reg = con.getRegister("sync");
			if (!lst.isUndefined(addr, addr)) {
				ClearCmd cmd = new ClearCmd(lst.getCodeUnitAt(addr), null);
				runCommand(cmd);
			}
			BigInteger val = BigInteger.ONE;
			con.setValue(reg, addr, addr, val);
			disassemble(addr);
		}
	}
}

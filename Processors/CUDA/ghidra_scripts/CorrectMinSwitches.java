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

import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

public class CorrectMinSwitches extends GhidraScript {

	@Override
	public void run() throws Exception {
		if (currentProgram == null) return;
		final int maxIterations = 10;
		Address minAddr = getAddressFactory().getAddress("0");
		InstructionIterator instructions = currentProgram.getListing().getInstructions(minAddr, true);
		for (Instruction instr : instructions) {
			if (instr.getMnemonicString().indexOf("BRX") != -1) {
				String reg1 = instr.getRegister(0).getName();
				String reg2 = null;
				Instruction curInstr = instr.getPrevious();
				if (curInstr == null) continue;
				Instruction patchInstr = null;
				int i = 0;
				while (i < maxIterations) {
					if (curInstr.getMnemonicString().indexOf("LDC") != -1 &&
						curInstr.getRegister(0).getName().equals(reg1)) {
							if (curInstr == null) break;
							reg2 = ((Register) curInstr.getInputObjects()[0]).getName();
							curInstr = curInstr.getPrevious();
							i = 0;
							break;
					}
					curInstr = curInstr.getPrevious();
					if (curInstr == null) break;
					i++;
				}
				if (reg2 == null) continue;
				while (i < maxIterations) {
					if (curInstr.getMnemonicString().indexOf("IMNMX") != -1 &&
						curInstr.getRegister(0).getName().equals(reg2)) {
							patchInstr = curInstr;
							break;
					}
					curInstr = curInstr.getPrevious();
					if (curInstr == null) break;
					i++;
				}
				if (patchInstr == null) continue;
				reg1 = patchInstr.getRegister(0).getName();
				reg2 = patchInstr.getRegister(1).getName();
				String str1 = patchInstr.toString();
				String str2 = "MOV " + reg1 + "," + reg2;
				Address addr = patchInstr.getAddress();
				Assembler asm = Assemblers.getAssembler(currentProgram);
				byte[] b = asm.assembleLine(addr, str2);
				asm.patchProgram(b, addr);
				println("Patched at " + addr.toString());
				println("From: " + str1);
				println("To: " + str2);
			}
		}
	}
}

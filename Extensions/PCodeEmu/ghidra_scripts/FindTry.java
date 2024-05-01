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
//@category Exceptions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

import java.math.BigInteger;

public class FindTry extends GhidraScript {
	@Override
	protected void run() throws Exception {
		if (currentProgram.getLanguage().toString().startsWith("x86/little/32")) run_x86_32();
	}

	private void run_x86_32() {
		if (!validateFunctionStart_x86_32(currentAddress)) return;
	}

	private boolean validateFunctionStart_x86_32(Address address) {
		InstructionIterator iter = currentProgram.getListing().getInstructions(address, true);
		int count = 7;

		// Collect instructions at the start
		Instruction[] instructions = new Instruction[count];
		for (int i = 0; i < count; i++) {
			if (!iter.hasNext()) return false;
			instructions[i] = iter.next();
		}

		// Find load instruction which uses FS at 0 offset
		int loadExceptionListIndex = -1;
		for (int i = 0; i < count; i++) {
			Instruction instruction = instructions[i];
			if (instruction.toString().equals("MOV EAX,FS:[0x0]")) {
				loadExceptionListIndex = i;
				break;
			}
		}
		if (loadExceptionListIndex < 2) return false;

		// There must be push for initializer before fs:[0] loading
		int setInitializerPointerIndex = loadExceptionListIndex - 1;
		if (!instructions[setInitializerPointerIndex].toString().startsWith("PUSH 0x")) return false;
		String pointerString = instructions[setInitializerPointerIndex].toString().substring("PUSH 0x".length());
		BigInteger pointerValue = new BigInteger(pointerString, 16);

		// There must be another push with -1 before this one
		int clearTryIndex = setInitializerPointerIndex - 1;
		if (!instructions[clearTryIndex].toString().equals("PUSH -0x1")) return false;
		return true;
	}
}

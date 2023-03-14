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
package util;

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
		ProgramContext con = currentProgram.getProgramContext();
		Register reg1 = con.getRegister("exceptFlag");
		Register reg2 = con.getRegister("exceptOffset");
		if (reg1 == null || reg2 == null) return;
		Listing lst = currentProgram.getListing();
		if (currentSelection == null) {
			if (currentAddress != null) {
				if (lst.isUndefined(currentAddress, currentAddress)) return;

				long length = lst.getCodeUnitAt(currentAddress).getLength();
				if (length <= 0) return;

				ClearCmd cmd = new ClearCmd(lst.getCodeUnitAt(currentAddress), null);
				runCommand(cmd);

				BigInteger val1 = BigInteger.ZERO;
				BigInteger val2 = BigInteger.ZERO;

				con.setValue(reg1, currentAddress, currentAddress, val1);
				con.setValue(reg2, currentAddress, currentAddress, val2);

				waitReg(con, reg1, currentAddress, val1);
				waitReg(con, reg2, currentAddress, val2);

				disassemble(currentAddress);
			}
		}
		else {
			Address start = currentSelection.getMinAddress();
			if (lst.isUndefined(start, start)) return;

			long length = lst.getCodeUnitAt(start).getLength();
			if (length <= 0) return;

			Address end = currentSelection.getMaxAddress();
			long offset = end.getOffset() - start.getOffset() - length + 1;

			ClearCmd cmd = new ClearCmd(lst.getCodeUnitAt(start), null);
			runCommand(cmd);

			BigInteger val1 = BigInteger.ONE;
			BigInteger val2 = BigInteger.valueOf(offset);

			con.setValue(reg1, start, start, val1);
			con.setValue(reg2, start, start, val2);

			waitReg(con, reg1, start, val1);
			waitReg(con, reg2, start, val2);

			disassemble(start);
		}
	}

	/**
	 * Waits until the given register recieves its correct value.
	 * @param con the program context object.
	 * @param reg the pending register.
	 * @param addr the address at which to wait for a value.
	 * @param val the new register value to wait for.
	 * @return amount of value fetches required.
	 */
	private long waitReg(ProgramContext con, Register reg, Address addr, BigInteger val) {
		boolean signed = val.compareTo(BigInteger.ZERO) < 0; // Only negative values require a sign
		BigInteger cur = con.getValue(reg, addr, signed);
		long repeats = 0;
		while (cur == null || !cur.equals(val)) {
			cur = con.getValue(reg, addr, signed);
			repeats++;
		}
		return repeats;
	}
}

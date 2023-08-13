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
package ghidra.pcode.utils;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.*;
import ghidra.app.plugin.core.clear.ClearCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.util.UndefinedFunction;
import ghidra.util.task.TaskMonitor;

import java.math.BigInteger;

public class PcodeUtils {
	/**
	 * Waits until the given register recieves its correct value.
	 * @param con the program context object.
	 * @param reg the pending register.
	 * @param addr the address at which to wait for a value.
	 * @param val the new register value to wait for.
	 * @return amount of value fetches required.
	 */
	public static long waitContextRegister(ProgramContext con, Register reg, Address addr, BigInteger val) {
		boolean signed = val.compareTo(BigInteger.ZERO) < 0; // Only negative values require a sign
		BigInteger cur = con.getValue(reg, addr, signed);
		long repeats = 0;
		while (cur == null || !cur.equals(val)) {
			cur = con.getValue(reg, addr, signed);
			repeats++;
		}
		return repeats;
	}

	public static void setContextRegister(Program program, TaskMonitor monitor, Register register, BigInteger value, Address address) {
		try {
			Listing listing = program.getListing();
			if (listing.isUndefined(address, address)) return;
			long length = listing.getCodeUnitAt(address).getLength();
			if (length <= 0) return;

			ClearCmd clearCmd = new ClearCmd(listing.getCodeUnitAt(address), null);
			clearCmd.applyTo(program, monitor);

			ProgramContext context = program.getProgramContext();
			context.setValue(register, address, address, value);
			waitContextRegister(context, register, address, value);

			DisassembleCommand disassembleCommand = new DisassembleCommand(address, null, true);
			disassembleCommand.applyTo(program, monitor);
		} catch (ContextChangeException e) {}
	}

	public static String getDecompiledC(Program program, Address address, TaskMonitor monitor) {
		DecompileOptions options = new DecompileOptions();
		DecompInterface ifc = new DecompInterface();
		ifc.setOptions(options);
		ifc.setSimplificationStyle("decompile");
		if (!ifc.openProgram(program)) {
			return null;
		}
		Function func = findFunction(program, address, monitor);
		if (func == null) {
			return null;
		}
		DecompileResults dr = ifc.decompileFunction(func, options.getDefaultTimeout(), monitor);
		return dr.getDecompiledFunction().getC();
	}

	public static Function findFunction(Program program, Address address, TaskMonitor monitor) {
		if (program == null) {
			return null;
		}

		if (address == null) {
			return null;
		}

		if (monitor.isCancelled()) {
			return null;
		}

		Function function = program.getFunctionManager().getFunctionContaining(address);
		if (function != null) {
			return function;
		}

		function = UndefinedFunction.findFunction(program, address, monitor);
		if (function != null) {
			// Make sure there isn't a real function at the location found
			// function may not contain currentAddress in its body.
			// This will cause provider to re-decompile when
			// clicking around the currentAddress :(
			Function realFunction =
					program.getFunctionManager().getFunctionAt(function.getEntryPoint());
			if (realFunction != null) {
				return realFunction;
			}
		}

		return function;
	}
}

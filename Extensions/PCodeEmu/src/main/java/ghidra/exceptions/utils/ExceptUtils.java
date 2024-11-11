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
package ghidra.exceptions.utils;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.*;
import ghidra.app.plugin.core.clear.ClearCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.util.UndefinedFunction;
import ghidra.util.task.TaskMonitor;

import java.math.BigInteger;

public class ExceptUtils {
	public static final int FLAG_CLEARED	= 0;
	public static final int FLAG_TRY		= 1;
	public static final int FLAG_CATCH		= 2;
	public static final int FLAG_EXCEPT		= 3;
	public static final int FLAG_ON			= 4;
	public static final int FLAG_FINALLY	= 5;
	public static final int FLAG_MIN		= FLAG_TRY;
	public static final int FLAG_MAX		= FLAG_FINALLY;

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
	/**
	 * Waits until the given register recieves its correct value.
	 * @param con the program context object.
	 * @param reg the pending register.
	 * @param addr the address at which to wait for a value.
	 * @param val the new register value to wait for.
	 * @return amount of value fetches required.
	 */
	public static long waitContextRegister(ProgramContext con, TaskMonitor monitor, Register reg, Address addr, BigInteger val) {
		boolean signed = val.compareTo(BigInteger.ZERO) < 0; // Only negative values require a sign
		BigInteger cur = con.getValue(reg, addr, signed);
		long repeats = 0;
		while (cur == null || !cur.equals(val)) {
			if (monitor.isCancelled()) {
				return repeats;
			}
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
			waitContextRegister(context, monitor, register, address, value);

			if (monitor.isCancelled()) {
				return;
			}

			DisassembleCommand disassembleCommand = new DisassembleCommand(address, null, true);
			disassembleCommand.applyTo(program, monitor);
		} catch (ContextChangeException e) {}
	}

	/**
	 * Sets values triple to define part of exception related code
	 * @param program the program.
	 * @param monitor the task monitor.
	 * @param address the address at which context registers are set.
	 * @param valFlag the value for register "exceptFlag".
	 * @param valOffset the value for register "exceptOffset".
	 * @param valVariant the value for register "exceptVariant".
	 */
	public static void setFlags(Program program, TaskMonitor monitor, Address address,
								BigInteger valFlag, BigInteger valOffset, BigInteger valVariant) {
		ProgramContext context = program.getProgramContext();
		Register reg1 = context.getRegister("exceptFlag");
		Register reg2 = context.getRegister("exceptOffset");
		Register reg3 = context.getRegister("exceptVariant");

		setContextRegister(program, monitor, reg1, valFlag, address);
		setContextRegister(program, monitor, reg2, valOffset, address);
		setContextRegister(program, monitor, reg3, valVariant, address);
	}

	public static void setFlags(Program program, TaskMonitor monitor, Address start, Address end, int flag, int variant) {
		if (start == null) {
			return;
		}
		if (flag < FLAG_MIN || flag > FLAG_MAX) { // Assume we are clearing if invalid flag was passed
			BigInteger val1 = BigInteger.valueOf(0);
			BigInteger val2 = BigInteger.valueOf(0);
			BigInteger val3 = BigInteger.valueOf(0);
			setFlags(program, monitor, start, val1, val2, val3);
			return;
		}

		Listing lst = program.getListing();
		long length = lst.getCodeUnitAt(start).getLength();

		if (end == null || start.equals(end)) { // Assume end is next instruction
			end = start.add(length - 1);
		}

		long offset = end.getOffset() - start.getOffset() - length + 1;

		BigInteger val1 = BigInteger.valueOf(flag);
		BigInteger val2 = BigInteger.valueOf(offset);
		BigInteger val3 = BigInteger.valueOf(variant);
		setFlags(program, monitor, start, val1, val2, val3);
	}

	public static void setCatchFlags(Program program, TaskMonitor monitor, Address start, Address end) {
		setFlags(program, monitor, start, end, FLAG_CATCH, 0);
		String str = getDecompiledC(program, start, monitor);
		if (str == null) {
			return;
		}
		if (!str.contains("!catch(")) {
			return;
		}
		setFlags(program, monitor, start, end, FLAG_CATCH, 1);
	}

	public static void setExceptFlags(Program program, TaskMonitor monitor, Address start, Address end) {
		setFlags(program, monitor, start, end, FLAG_EXCEPT, 0);
		String str = getDecompiledC(program, start, monitor);
		if (str == null) {
			return;
		}
		if (!str.contains("!except(")) {
			return;
		}
		setFlags(program, monitor, start, end, FLAG_EXCEPT, 1);
	}

	public static void setOnFlags(Program program, TaskMonitor monitor, Address start, Address end) {
		setFlags(program, monitor, start, end, FLAG_ON, 0);
		String str = getDecompiledC(program, start, monitor);
		if (str == null) {
			return;
		}
		if (!str.contains("!except(")) {
			return;
		}
		setFlags(program, monitor, start, end, FLAG_ON, 1);
	}

}

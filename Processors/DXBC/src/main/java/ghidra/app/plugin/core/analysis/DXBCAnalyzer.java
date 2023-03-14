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
package ghidra.app.plugin.core.analysis;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.clear.ClearCmd;
import ghidra.program.database.ProgramCompilerSpec;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.util.ContextEvaluator;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class DXBCAnalyzer extends ConstantPropagationAnalyzer {

	private final static String PROCESSOR_NAME = "DXBC";

	private List<IfAddresses> ifList = new ArrayList();

	public DXBCAnalyzer() {
		super(PROCESSOR_NAME);
	}

	@Override
	public boolean canAnalyze(Program program) {
		if (!program.getLanguage().getProcessor().equals(
				Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME))) return false;
		int txId = program.startTransaction("Set Java mode");
		ProgramCompilerSpec.enableJavaLanguageDecompilation(program);
		program.endTransaction(txId, true);
		return true;
	}

	@Override
	public AddressSetView flowConstants(final Program program, Address flowStart, AddressSetView flowSet, final SymbolicPropogator symEval, final TaskMonitor monitor)
			throws CancelledException {
		ContextEvaluator eval = new ConstantPropagationContextEvaluator(trustWriteMemOption) {
			@Override
			public boolean evaluateContext(VarnodeContext context, Instruction instr) {
				String mnemonic = instr.getMnemonicString();
				Address addr = instr.getAddress();
				if (!isTaken(program, addr)) {
					markAsTaken(program, addr, monitor);
					if (mnemonic.equals("if_nz") || mnemonic.equals("if_z")) {
						Address ifAddr = addr;
						if (!ifList.isEmpty()) {
							IfAddresses entry = ifList.get(ifList.size() - 1);
							if (ifAddr.getOffset() == entry.ifAddr.getOffset())
								return false;
						}
						ifList.add(new IfAddresses(ifAddr));
					}
					if (mnemonic.equals("else") && ifList.size() != 0) {
						Address elseAddr = addr;
						IfAddresses entry = ifList.get(ifList.size() - 1);
						entry.elseAddr = elseAddr;
						Address ifAddr = entry.ifAddr;
						setOffset(program, ifAddr, elseAddr.subtract(ifAddr) + instr.getLength(), monitor);
					}
					if (mnemonic.equals("endif") && ifList.size() != 0) {
						Address endifAddr = addr;
						IfAddresses entry = ifList.get(ifList.size() - 1);
						Address ifAddr = entry.ifAddr;
						Address elseAddr = entry.elseAddr;
						if (elseAddr == null) {
							setOffset(program, ifAddr, endifAddr.subtract(ifAddr), monitor);
						} else {
							setOffset(program, elseAddr, endifAddr.subtract(elseAddr), monitor);
						}
						ifList.remove(ifList.size() - 1);
					}
				}
				return false;
			}
		};
		AddressSet resultSet = symEval.flowConstants(flowStart, flowSet, eval, true, monitor);

		return resultSet;
	}

	private boolean isTaken(Program program, Address addr) {
		ProgramContext con = program.getProgramContext();
		Register reg = con.getRegister("taken");
		BigInteger val = con.getValue(reg, addr, false);
		if (val == null) return false;
		return !val.equals(BigInteger.ZERO);
	}

	private void markAsTaken(Program program, Address addr, TaskMonitor monitor) {
		try {
			if (!program.getListing().isUndefined(addr, addr)) {
				ClearCmd cmd = new ClearCmd(program.getListing().getCodeUnitAt(addr), null);
				cmd.applyTo(program, monitor);
			}
			ProgramContext con = program.getProgramContext();
			Register reg = con.getRegister("taken");
			con.setValue(reg, addr, addr, BigInteger.ONE);
			DisassembleCommand cmd = new DisassembleCommand(addr, null, true);
			cmd.applyTo(program, monitor);
		} catch (Exception e) {}
	}

	private void setOffset(Program program, Address addr, long off, TaskMonitor monitor) {
		try {
			if (!program.getListing().isUndefined(addr, addr)) {
				ClearCmd cmd = new ClearCmd(program.getListing().getCodeUnitAt(addr), null);
				cmd.applyTo(program, monitor);
			}
			ProgramContext con = program.getProgramContext();
			Register reg = con.getRegister("offs");
			BigInteger val = new BigInteger(String.valueOf(off));
			con.setValue(reg, addr, addr, val);
			DisassembleCommand cmd = new DisassembleCommand(addr, null, true);
			cmd.applyTo(program, monitor);
		} catch (Exception e) {}
	}

	private class IfAddresses {
		public Address ifAddr;
		public Address elseAddr;

		public IfAddresses(Address ifAddr) {
			this.ifAddr = ifAddr;
		}
	}
}

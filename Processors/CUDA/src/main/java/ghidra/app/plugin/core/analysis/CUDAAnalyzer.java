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
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
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

public class CUDAAnalyzer extends ConstantPropagationAnalyzer {

	private final static String PROCESSOR_NAME = "CUDA";

	public CUDAAnalyzer() {
		super(PROCESSOR_NAME);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().equals(
				Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));
	}

	@Override
	public AddressSetView flowConstants(final Program program, Address flowStart, AddressSetView flowSet, final SymbolicPropogator symEval, final TaskMonitor monitor)
			throws CancelledException {
		ContextEvaluator eval = new ConstantPropagationContextEvaluator(monitor, trustWriteMemOption) {
			@Override
			public boolean evaluateContext(VarnodeContext context, Instruction instr) {
				String mnemonic = instr.getMnemonicString();
				if (mnemonic.equals("SSY")) {
					AddressSpace space = instr.getAddress().getAddressSpace();
					try {
						Address addr = space.getAddress(instr.getOpObjects(0)[0].toString());
						Program program = instr.getProgram();
						if (!program.getListing().isUndefined(addr, addr)) {
							ClearCmd cmd = new ClearCmd(program.getListing().getCodeUnitAt(addr), null);
							cmd.applyTo(program, monitor);
						}
						BigInteger val = BigInteger.ONE;
						ProgramContext con = program.getProgramContext();
						Register reg = con.getRegister("sync");
						con.setValue(reg, addr, addr, val);
						DisassembleCommand cmd = new DisassembleCommand(addr, null, true);
						cmd.applyTo(program, monitor);
					} catch (Exception e) {}
				}
				return false;
			}
		};
		AddressSet resultSet = symEval.flowConstants(flowStart, flowSet, eval, true, monitor);

		return resultSet;
	}
}

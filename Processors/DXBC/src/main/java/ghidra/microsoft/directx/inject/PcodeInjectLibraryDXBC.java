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
package ghidra.microsoft.directx.inject;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.ConstantPool;
import ghidra.program.model.lang.PcodeInjectLibrary;
import ghidra.program.model.listing.Program;

import java.io.IOException;

public class PcodeInjectLibraryDXBC extends PcodeInjectLibrary {

	public PcodeInjectLibraryDXBC(SleighLanguage l) { super(l); }

	public PcodeInjectLibraryDXBC(PcodeInjectLibraryDXBC op2) { super(op2); }

	@Override
	public PcodeInjectLibrary clone() {
		return new PcodeInjectLibraryDXBC(this);
	}

	@Override
	public ConstantPool getConstantPool(Program program) throws IOException {
		return new ConstantPoolDXBC(program);
	}

}

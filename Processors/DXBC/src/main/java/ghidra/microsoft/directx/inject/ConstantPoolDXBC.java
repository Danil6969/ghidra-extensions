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

import ghidra.program.model.data.*;
import ghidra.program.model.lang.ConstantPool;
import ghidra.program.model.listing.Program;

public class ConstantPoolDXBC extends ConstantPool {

	public ConstantPoolDXBC(Program program) {}

	@Override
	public Record getRecord(long[] ref) {
		Record res = new Record();
		res.tag = ConstantPool.POINTER_FIELD;
		if (ref[1] == 0)
			res.token = getOutputVecToken(ref[2]);
		if (ref[1] == 1)
			res.token = getInputVecToken(ref[2], ref[3]);
		DataType dt = new Undefined4DataType();
		if (ref[0] == 0)
			dt = new UnsignedIntegerDataType();
		if (ref[0] == 1)
			dt = new Float4DataType();
		if (ref[0] == 2)
			dt = new IntegerDataType();
		res.type = new PointerDataType(dt);
		return res;
	}

	private String getInputVecToken(long n, long m) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < 4; i++, n >>= 2) {
			if ((m >> i & 1) == 0) continue;
			if ((n & 3) == 0) sb.append('x');
			if ((n & 3) == 1) sb.append('y');
			if ((n & 3) == 2) sb.append('z');
			if ((n & 3) == 3) sb.append('w');
		}
		return sb.toString();
	}

	private String getOutputVecToken(long n) {
		StringBuilder sb = new StringBuilder();
		if ((n & 1) != 0)
			sb.append('x');
		if ((n >> 1 & 1) != 0)
			sb.append('y');
		if ((n >> 2 & 1) != 0)
			sb.append('z');
		if ((n >> 3 & 1) != 0)
			sb.append('w');
		return sb.toString();
	}
}

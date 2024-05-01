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

import ghidra.app.script.GhidraScript;
import ghidra.pcode.floatformat.BigFloat;
import ghidra.pcode.floatformat.FloatFormat;
import ghidra.pcode.floatformat.FloatFormatFactory;

import java.math.BigDecimal;
import java.math.BigInteger;

public class TestBigFloat extends GhidraScript {
	@Override
	public void run() throws Exception {
		BigDecimal bd = new BigDecimal("1.00000000000000000").divide(new BigDecimal("256"));
		FloatFormat ff = FloatFormatFactory.getFloatFormat(10);
		BigFloat bf = ff.getBigFloat(bd);
		int fracbits = 64;
		BigInteger exp = ff.getEncoding(bf).shiftRight(4*16);
		int scale = exp.intValue() - 0x3FFF;
		BigFloat half = ff.getBigFloat(new BigDecimal("0.5"));
		BigFloat tolerance = half.copy();
		for (int i = 1; i < fracbits - scale; i++)
			tolerance.mul(half);
		bf.add(tolerance);
		return;
	}
}

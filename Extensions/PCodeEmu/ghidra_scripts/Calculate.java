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
import ghidra.pcode.utils.BigDecimalUtil;

import java.math.BigDecimal;
import java.math.BigInteger;

public class Calculate extends GhidraScript {
	@Override
	public void run() throws Exception {
		final int numDigits = 16;
		int constIndex = 0;
		String str;
		char c;
		int i;
		BigDecimal n1;
		BigInteger n2;
		BigDecimal n3;
		while (constIndex < 5) {
			n1 = fetchConstant(constIndex);
			n1 = prepareConstant(n1, constIndex);
			for (i = 0; i < numDigits; i++) {
				n1 = n1.multiply(new BigDecimal("16.0"));
			}
			n2 = n1.toBigInteger();
			str = n2.toString(16);
			println(str);
			//check
			n1 = BigDecimal.ZERO;
			n3 = BigDecimal.ONE;
			for (i = 0; i < numDigits; i++) {
				n2 = new BigInteger(str.substring(i, i+1), 16);
				n3 = n3.divide(new BigDecimal("16.0"), BigDecimalUtil.SCALE, BigDecimal.ROUND_HALF_EVEN);
				n1 = n1.add((new BigDecimal(n2).multiply(n3)));
			}
			str = adjustConstant(n1, constIndex).stripTrailingZeros().toString();
			println("Restored \""+ getName(constIndex) + "\" constant: " + str);
			println();
			constIndex++;
		}
		// L2T: 0.d49a784bcd1b8afe * 2^2;    biased exp: 0x4000
		// L2E: 0.b8aa3b295c17f0bb * 2^1;    biased exp: 0x3fff
		// PI:  0.c90fdaa22168c234 * 2^2;    biased exp: 0x4000
		// LG2: 0.9a209a84fbcff798 * 2^(-1); biased exp: 0x3ffd
		// LN2: 0.b17217f7d1cf79ab * 2^0;    biased exp: 0x3ffe
		// Restored values
		// L2T: 3.3219280948873623478083405569094566089916042983531951904296875
		// L2E: 1.442695040888963407279231565549793003810918889939785003662109375
		// PI:  3.141592653589793238295968524909085317631252110004425048828125
		// LG2: 0.30102999566398119519854137404735183736192993819713592529296875
		// LN2: 0.6931471805599453093744803655607000791860627941787242889404296875
	}

	private BigDecimal fetchConstant(int index) {
		BigDecimal constant = null;
		switch (index) {
			case 0:
				//L2T
				constant = BigDecimalUtil.log(new BigDecimal("2.0"), new BigDecimal("10.0"));
				break;
			case 1:
				//L2E
				constant = BigDecimal.ONE.divide(BigDecimalUtil.ln(new BigDecimal("2.0"), BigDecimalUtil.SCALE), BigDecimalUtil.SCALE, BigDecimal.ROUND_HALF_EVEN);
				break;
			case 2:
				//PI
				constant = BigDecimalUtil.getPi(BigDecimalUtil.SCALE);
				break;
			case 3:
				//LG2
				constant = BigDecimalUtil.log(new BigDecimal("10.0"), new BigDecimal("2.0"));
				break;
			case 4:
				//LN2
				constant = BigDecimalUtil.ln(new BigDecimal("2.0"), BigDecimalUtil.SCALE);
				break;
		}
		return constant;
	}

	private BigDecimal prepareConstant(BigDecimal in, int index) {
		BigDecimal multiplier = new BigDecimal("0.0");
		switch (index) {
			case 0:
				//L2T
				multiplier = new BigDecimal("0.25");
				break;
			case 1:
				//L2E
				multiplier = new BigDecimal("0.5");
				break;
			case 2:
				//PI
				multiplier = new BigDecimal("0.25");
				break;
			case 3:
				//LG2
				multiplier = new BigDecimal("2.0");
				break;
			case 4:
				//LN2
				multiplier = new BigDecimal("1.0");
				break;
		}
		return in.multiply(multiplier);
	}

	private BigDecimal adjustConstant(BigDecimal in, int index) {
		BigDecimal multiplier = new BigDecimal("0.0");
		switch (index) {
			case 0:
				//L2T
				multiplier = new BigDecimal("4.0");
				break;
			case 1:
				//L2E
				multiplier = new BigDecimal("2.0");
				break;
			case 2:
				//PI
				multiplier = new BigDecimal("4.0");
				break;
			case 3:
				//LG2
				multiplier = new BigDecimal("0.5");
				break;
			case 4:
				//LN2
				multiplier = new BigDecimal("1.0");
				break;
		}
		return in.multiply(multiplier);
	}

	private String getName(int index) {
		String name = null;
		switch (index) {
			case 0:
				name = "L2T";
				break;
			case 1:
				name = "L2E";
				break;
			case 2:
				name = "PI";
				break;
			case 3:
				name = "LG2";
				break;
			case 4:
				name = "LN2";
				break;
		}
		return name;
	}
}

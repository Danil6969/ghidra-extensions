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
package ghidra.program.emulation.relocation;

public class PeRelocationConstants {
	public final static short LDRP_RELOCATION_FINAL = 2;

	// Intel-IA64-Filler
	public final static long EMARCH_ENC_I17_IMM7B_INST_WORD_X = 3;
	public final static int EMARCH_ENC_I17_IMM7B_SIZE_X = 7;
	public final static int EMARCH_ENC_I17_IMM7B_INST_WORD_POS_X = 4;
	public final static int EMARCH_ENC_I17_IMM7B_VAL_POS_X = 0;

	public final static long EMARCH_ENC_I17_IMM9D_INST_WORD_X = 3;
	public final static int EMARCH_ENC_I17_IMM9D_SIZE_X = 9;
	public final static int EMARCH_ENC_I17_IMM9D_INST_WORD_POS_X = 18;
	public final static int EMARCH_ENC_I17_IMM9D_VAL_POS_X = 7;

	public final static long EMARCH_ENC_I17_IMM5C_INST_WORD_X = 3;
	public final static int EMARCH_ENC_I17_IMM5C_SIZE_X = 5;
	public final static int EMARCH_ENC_I17_IMM5C_INST_WORD_POS_X = 13;
	public final static int EMARCH_ENC_I17_IMM5C_VAL_POS_X = 16;

	public final static long EMARCH_ENC_I17_IC_INST_WORD_X = 3;
	public final static int EMARCH_ENC_I17_IC_SIZE_X = 1;
	public final static int EMARCH_ENC_I17_IC_INST_WORD_POS_X = 12;
	public final static int EMARCH_ENC_I17_IC_VAL_POS_X = 21;

	public final static long EMARCH_ENC_I17_IMM41a_INST_WORD_X = 1;
	public final static int EMARCH_ENC_I17_IMM41a_SIZE_X = 10;
	public final static int EMARCH_ENC_I17_IMM41a_INST_WORD_POS_X = 14;
	public final static int EMARCH_ENC_I17_IMM41a_VAL_POS_X = 22;

	public final static long EMARCH_ENC_I17_IMM41b_INST_WORD_X = 1;
	public final static int EMARCH_ENC_I17_IMM41b_SIZE_X = 8;
	public final static int EMARCH_ENC_I17_IMM41b_INST_WORD_POS_X = 24;
	public final static int EMARCH_ENC_I17_IMM41b_VAL_POS_X = 32;

	public final static long EMARCH_ENC_I17_IMM41c_INST_WORD_X = 2;
	public final static int EMARCH_ENC_I17_IMM41c_SIZE_X = 23;
	public final static int EMARCH_ENC_I17_IMM41c_INST_WORD_POS_X = 0;
	public final static int EMARCH_ENC_I17_IMM41c_VAL_POS_X = 40;

	public final static long EMARCH_ENC_I17_SIGN_INST_WORD_X = 3;
	public final static int EMARCH_ENC_I17_SIGN_SIZE_X = 1;
	public final static int EMARCH_ENC_I17_SIGN_INST_WORD_POS_X = 27;
	public final static int EMARCH_ENC_I17_SIGN_VAL_POS_X = 63;
}

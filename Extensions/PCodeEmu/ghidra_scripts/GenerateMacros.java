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
import ghidra.exceptions.utils.ExceptUtils;

import java.util.ArrayList;
import java.util.List;

public class GenerateMacros extends GhidraScript {
	List<String> macros;

	@Override
	public void run() throws Exception {
		String str = ExceptUtils.getDecompiledC(currentProgram, currentAddress, monitor);
		processCOPY(str);
		processTOARR(str);
		processCONCAT(str);
		processSUB(str);
		processZEXT(str);
		processSEXT(str);
	}

	private void printList(List<String> list) {
		for (String element : list)
			print(element + "\n");
		print("\n");
	}

	private void processCOPY(String str) {
		macros = new ArrayList();
		for (int index = str.indexOf("COPY"); index != -1; index = str.indexOf("COPY", index + 1)) {
			String macro = str.substring(index, str.indexOf("(", index));
			String n = macro.substring(4);
			macro = "#define " + macro +  "(a, x) COPY(a, x, " + n + ")";
			if (!macros.contains(macro))
				macros.add(macro);
		}
		if (macros.size() > 0)
			printList(macros);
	}

	private void processTOARR(String str) {
		macros = new ArrayList();
		for (int index = str.indexOf("TOARR"); index != -1; index = str.indexOf("TOARR", index + 1)) {
			String macro = str.substring(index, str.indexOf("(", index));
			String n = macro.substring(5);
			macro = "#define " + macro +  "(x, t) TOARR(x, t, " + n + ")";
			if (!macros.contains(macro))
				macros.add(macro);
		}
		if (macros.size() > 0)
			printList(macros);
	}

	private void processCONCAT(String str) {
		macros = new ArrayList();
		for (int index = str.indexOf("CONCAT"); index != -1; index = str.indexOf("CONCAT", index + 1)) {
			String macro = str.substring(index, str.indexOf("(", index));
			boolean typed = macro.charAt(macro.length() - 1) == 'T';
			String n = macro.substring(6);
			String n1 = n.substring(0, n.indexOf("_"));
			String n2;
			if (typed)
				n2 = n.substring(n.indexOf("_") + 1, n.length() - 1);
			else
				n2 = n.substring(n.indexOf("_") + 1);
			n = Integer.toString(Integer.parseInt(n1) + Integer.parseInt(n2));
			if (typed)
				macro = "#define " + macro + "(x, y, t) CONCATT(x, y, " + n1 + ", " + n2 + ", " + n + ", t)";
			else
				macro = "#define " + macro + "(x, y) CONCATN(x, y, " + n1 + ", " + n2 + ", " + n + ")";
			if (!macros.contains(macro))
				macros.add(macro);
		}
		if (macros.size() > 0)
			printList(macros);
	}

	private void processSUB(String str) {
		macros = new ArrayList();
		for (int index = str.indexOf("SUB"); index != -1; index = str.indexOf("SUB", index + 1)) {
			String macro = str.substring(index, str.indexOf("(", index));
			boolean typed = macro.charAt(macro.length() - 1) == 'T';
			String n = macro.substring(3);
			String n1 = n.substring(0, n.indexOf("_"));
			String n2;
			if (typed)
				n2 = n.substring(n.indexOf("_") + 1, n.length() - 1);
			else
				n2 = n.substring(n.indexOf("_") + 1);
			if (typed)
				macro = "#define " + macro + "(x, n, t) SUBT(x, n, " + n1 + ", " + n2 + ", t)";
			else
				macro = "#define " + macro + "(x, n) SUBN(x, n, " + n1 + ", " + n2 + ")";
			if (!macros.contains(macro))
				macros.add(macro);
		}
		if (macros.size() > 0)
			printList(macros);
	}

	private void processZEXT(String str) {
		macros = new ArrayList();
		for (int index = str.indexOf("ZEXT"); index != -1; index = str.indexOf("ZEXT", index + 1)) {
			String macro = str.substring(index, str.indexOf("(", index));
			boolean typed = macro.charAt(macro.length() - 1) == 'T';
			String n = macro.substring(4);
			String n1 = n.substring(0, n.indexOf("_"));
			String n2;
			if (typed)
				n2 = n.substring(n.indexOf("_") + 1, n.length() - 1);
			else
				n2 = n.substring(n.indexOf("_") + 1);
			if (typed)
				macro = "#define " + macro + "(x, t) ZEXTT(x, " + n1 + ", " + n2 + ", t)";
			else
				macro = "#define " + macro + "(x) ZEXTN(x, " + n1 + ", " + n2 + ")";
			if (!macros.contains(macro))
				macros.add(macro);
		}
		if (macros.size() > 0)
			printList(macros);
	}

	private void processSEXT(String str) {
		macros = new ArrayList();
		for (int index = str.indexOf("SEXT"); index != -1; index = str.indexOf("SEXT", index + 1)) {
			String macro = str.substring(index, str.indexOf("(", index));
			boolean typed = macro.charAt(macro.length() - 1) == 'T';
			String n = macro.substring(4);
			String n1 = n.substring(0, n.indexOf("_"));
			String n2;
			if (typed)
				n2 = n.substring(n.indexOf("_") + 1, n.length() - 1);
			else
				n2 = n.substring(n.indexOf("_") + 1);
			if (typed)
				macro = "#define " + macro + "(x, t) SEXTT(x, " + n1 + ", " + n2 + ", t)";
			else
				macro = "#define " + macro + "(x) SEXTN(x, " + n1 + ", " + n2 + ")";
			if (!macros.contains(macro))
				macros.add(macro);
		}
		if (macros.size() > 0)
			printList(macros);
	}
}

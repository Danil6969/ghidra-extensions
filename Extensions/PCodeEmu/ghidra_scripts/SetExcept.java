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
//@category Exceptions
package exceptions;

import ghidra.exceptions.utils.ExceptUtils;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

import java.math.BigInteger;

public class SetExcept extends GhidraScript {
	@Override
	protected void run() throws Exception {
		Listing lst = currentProgram.getListing();
		if (currentSelection == null) {
			if (currentAddress != null) {
				ExceptUtils.setExceptFlags(currentProgram, monitor, currentAddress, null);
			}
		}
		else {
			Address start = currentSelection.getMinAddress();
			Address end = currentSelection.getMaxAddress();
			ExceptUtils.setExceptFlags(currentProgram, monitor, start, end);
		}
	}
}

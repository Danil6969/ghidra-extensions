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
package ghidra.program.emulation;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginException;

import java.util.Iterator;
import java.util.List;

public class PluginUtils {

	public static <T extends Plugin> T getOrAddPlugin(PluginTool tool, Class<T> c) {
		try {
			if (getPlugin(tool, c) == null) {
				tool.addPlugin(c.getName());
			}
		}
		catch (PluginException e) {
			return null;
		}
		return getPlugin(tool, c);
	}

	private static <T extends Plugin> T getPlugin(PluginTool tool, Class<T> c) {
		List<Plugin> list = tool.getManagedPlugins();
		Iterator<Plugin> it = list.iterator();
		while (it.hasNext()) {
			Plugin p = it.next();
			if (p.getClass() == c) {
				return c.cast(p);
			}
		}
		return null;
	}
}

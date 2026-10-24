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
package sega;

import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.opinion.Loader;

/**
 * Optional parts of the Mega Drive memory map. Offered in the import dialog and settable in a
 * headless import, e.g.
 * {@code -loader SegaLoader -loader-32x true -loader-sram-file save.srm}.
 */
record SegaLoadOptions(boolean create32XSegments, boolean createSegaCDSegments,
		boolean createHardwareRegisters, boolean verify, String sramFile) {

	static final String NAME_32X = "Create Sega 32X segments";
	static final String NAME_SEGA_CD = "Create Sega CD (EPA) segment";
	static final String NAME_HW_REGISTERS = "Create hardware register blocks";
	static final String NAME_VERIFY = "Verify the ROM header";
	static final String NAME_SRAM_FILE = "Backup RAM contents file (.srm / .sram)";

	static final String ARG_32X = Loader.COMMAND_LINE_ARG_PREFIX + "-32x";
	static final String ARG_SEGA_CD = Loader.COMMAND_LINE_ARG_PREFIX + "-sega-cd";
	static final String ARG_HW_REGISTERS = Loader.COMMAND_LINE_ARG_PREFIX + "-hw-registers";
	static final String ARG_VERIFY = Loader.COMMAND_LINE_ARG_PREFIX + "-verify";
	static final String ARG_SRAM_FILE = Loader.COMMAND_LINE_ARG_PREFIX + "-sram-file";

	static List<Option> options(boolean default32X, boolean defaultSegaCD) {
		return List.of(
			new Option(NAME_32X, default32X, Boolean.class, ARG_32X),
			new Option(NAME_SEGA_CD, defaultSegaCD, Boolean.class, ARG_SEGA_CD),
			new Option(NAME_HW_REGISTERS, true, Boolean.class, ARG_HW_REGISTERS),
			new Option(NAME_VERIFY, true, Boolean.class, ARG_VERIFY),
			new Option(NAME_SRAM_FILE, "", String.class, ARG_SRAM_FILE));
	}

	static SegaLoadOptions from(List<Option> options, boolean default32X, boolean defaultSegaCD) {
		return new SegaLoadOptions(getBoolean(options, NAME_32X, default32X),
			getBoolean(options, NAME_SEGA_CD, defaultSegaCD),
			getBoolean(options, NAME_HW_REGISTERS, true),
			getBoolean(options, NAME_VERIFY, true),
			getString(options, NAME_SRAM_FILE));
	}

	private static String getString(List<Option> options, String name) {
		if (options != null) {
			for (Option option : options) {
				if (name.equals(option.getName()) && option.getValue() instanceof String s
						&& !s.isBlank()) {
					return s.trim();
				}
			}
		}
		return null;
	}

	private static boolean getBoolean(List<Option> options, String name, boolean defaultValue) {
		if (options != null) {
			for (Option option : options) {
				if (name.equals(option.getName())) {
					return toBoolean(option.getValue(), defaultValue);
				}
			}
		}
		return defaultValue;
	}

	// Options that arrive from the command line are not always converted to their declared class.
	private static boolean toBoolean(Object value, boolean defaultValue) {
		if (value instanceof Boolean b) {
			return b;
		}
		if (value instanceof String s) {
			if (s.equalsIgnoreCase("true") || s.equals("1")) {
				return true;
			}
			if (s.equalsIgnoreCase("false") || s.equals("0")) {
				return false;
			}
		}
		return defaultValue;
	}
}

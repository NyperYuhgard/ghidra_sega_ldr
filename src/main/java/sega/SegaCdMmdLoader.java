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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadException;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.program.model.listing.Program;

/**
 * One file of the volume of a Sega CD disc, as a program of its own. The games of the machine carry
 * their sound drivers, their demo stages and the rest of their code as files of 68000 the console
 * reads off the disc and runs out of its own memory, and a disc hands a program the name of a file
 * and never the place it is carried to. So the file is asked for by name, the address by the person
 * reading the disc, and the map of the console is there around it because that is what its
 * references reach.
 */
public class SegaCdMmdLoader extends SegaCdLoaderBase {

	public static final String LOADER_NAME = "Sega CD Loader (Disc Member)";

	static final String NAME_MEMBER = "Disc member to import (ISO-9660 name)";
	static final String NAME_MEMBER_ADDRESS = "Address the member is loaded at";
	static final String ARG_MEMBER = Loader.COMMAND_LINE_ARG_PREFIX + "-cd-mmd";
	static final String ARG_MEMBER_ADDRESS = Loader.COMMAND_LINE_ARG_PREFIX + "-cd-mmd-address";

	// The dialog of an import shows every option of the loader together, and two of them belong to
	// the file asked for rather than to the disc it came off.
	private static final String GROUP_MEMBER = "The member of the volume";
	private static final String STATE_MEMBER = "Sega CD Disc Member";
	private static final String STATE_MEMBER_ADDRESS = "Sega CD Disc Member Address";

	@Override
	public String getName() {
		return LOADER_NAME;
	}

	@Override
	public int getTierPriority() {
		// A member is asked for by name, and never landed upon: an import of a disc that names no
		// loader wants the program its header declares, which is what the loader of the console is
		// for. Being preferred enough to be named at all, this one loses the choosing by priority.
		return 2;
	}

	@Override
	boolean isSubCpu() {
		return false;
	}

	@Override
	protected List<Option> memberOptions(ByteProvider provider) {
		List<String> names = memberNames(provider);
		// A field to type a name into, with six other fields around it, is a field that gets left
		// empty; the disc knows the names, so it is the one asked to show them.
		Option name = names.isEmpty()
			? new Option(NAME_MEMBER, String.class, "", ARG_MEMBER, GROUP_MEMBER, STATE_MEMBER,
				false)
			: new ListOption(NAME_MEMBER, firstOfKind(names), GROUP_MEMBER, ARG_MEMBER,
				STATE_MEMBER, names);
		Option address = new Option(NAME_MEMBER_ADDRESS, String.class, "", ARG_MEMBER_ADDRESS,
			GROUP_MEMBER, STATE_MEMBER_ADDRESS, false);
		return List.of(name, address);
	}

	/**
	 * What the box opens on. A volume lists its text and its sound before its code, so the first
	 * name of it is rarely the one worth a program; the kind this loader is named for comes first
	 * when the disc has any, and the rest of the list is one turn of the box away.
	 */
	private static String firstOfKind(List<String> names) {
		for (String name : names) {
			if (name.regionMatches(true, name.length() - 4, ".MMD", 0, 4)) {
				return name;
			}
		}
		return names.get(0);
	}

	/**
	 * The files of the volume of the file being imported, in the order the volume lists them. What
	 * is not a disc, what carries no volume and what cannot be read at all answer with nothing, and
	 * the option comes out as the plain field it was before any of this.
	 */
	private static List<String> memberNames(ByteProvider provider) {
		List<String> names = new ArrayList<>();
		CdImage disc;
		try {
			disc = CdImage.open(provider, new MessageLog());
		}
		catch (IOException e) {
			return List.of();
		}
		if (disc == null) {
			return List.of();
		}

		try {
			CdIso volume = CdIso.open(disc, new MessageLog());
			if (volume == null) {
				return List.of();
			}
			for (CdIso.Entry entry : volume.entries()) {
				if (!entry.directory()) {
					names.add(entry.path());
				}
			}
		}
		catch (IOException e) {
			return List.of();
		}
		finally {
			try {
				disc.close();
			}
			catch (IOException e) {
				// A dump that will not let go is not worth a word here: the importer closes it.
			}
		}
		return names;
	}

	@Override
	protected Member memberFor(ImporterSettings settings) throws LoadException {
		List<Option> options = settings.options();
		String name = SegaLoadOptions.getString(options, NAME_MEMBER);
		if (name == null) {
			throw refuse(String.format(
				"%s is not given: this loader imports one file of the volume of a disc. Choose the loader"
					+ " in Format, and only then press Options... and pick the file out of the box, which"
					+ " lists what the disc holds: changing Format afterwards empties whatever was"
					+ " answered. From a command line the same choice is %s ATTACK.MMD. Any import of a"
					+ " disc writes the files it holds into its log.",
				NAME_MEMBER, ARG_MEMBER));
		}

		String given = SegaLoadOptions.getString(options, NAME_MEMBER_ADDRESS);
		long address = addressOf(given);
		if (given != null && address < 0) {
			throw refuse(String.format(
				"'%s' is not an address of the console: write it as 0xFF2000, and no further than 0xFFFFFF, which is as far as its twenty four lines reach",
				given));
		}

		// An address left out is complained about where the volume is open and its files can be
		// listed with, which the missing one of them is the better for.
		return new Member(name, address);
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {

		String problem = super.validateOptions(provider, loadSpec, options, program);
		if (problem != null) {
			return problem;
		}
		if (SegaLoadOptions.getString(options, NAME_MEMBER) == null) {
			return NAME_MEMBER + ": the file of the disc to import, as ATTACK.MMD";
		}
		if (addressOf(SegaLoadOptions.getString(options, NAME_MEMBER_ADDRESS)) < 0) {
			return NAME_MEMBER_ADDRESS
				+ ": the disc does not say where a file of it is loaded, so the address has to be one of the memory of the console, as 0xFF2000";
		}
		return null;
	}

	/**
	 * An address of the console as it is written when there is nothing to read it from: the front
	 * that says hexadecimal is left to whoever types, and everything past six digits is not the
	 * address space of a processor with twenty four lines.
	 */
	private static long addressOf(String given) {
		if (given == null) {
			return -1;
		}

		String text = given;
		if (text.startsWith("0x") || text.startsWith("0X")) {
			text = text.substring(2);
		}
		else if (text.startsWith("$")) {
			text = text.substring(1);
		}
		if (text.isEmpty() || text.length() > 6) {
			return -1;
		}

		long value = 0;
		for (int i = 0; i < text.length(); i++) {
			int digit = Character.digit(text.charAt(i), 16);
			if (digit < 0) {
				return -1;
			}
			value = value * 16 + digit;
		}
		return value;
	}
}

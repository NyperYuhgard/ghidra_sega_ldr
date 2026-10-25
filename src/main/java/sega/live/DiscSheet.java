package sega.live;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.LinkedHashSet;
import java.util.Set;

import ghidra.program.model.listing.Program;
import sega.SegaCdMainLoader;
import sega.SegaCdMmdLoader;
import sega.SegaCdSubLoader;

/**
 * The disc a program was built from, as the emulator has to be given it. Ghidra reads the one track
 * of a Sega CD disc that carries a program — the dump its sheet points at — while BlastEm runs the
 * whole disc and wants that sheet. The two files name each other, and this is where the panel finds
 * one from the other.
 */
class DiscSheet {

	/** A disc is two 68000, and BlastEm keeps the blocks each of them reached in a log of its own. */
	private static final String CONSOLE_TRACE = "address.log";
	private static final String DRIVE_TRACE = "address_sub.log";

	/** A sheet is a few hundred lines of text; nothing longer is describing this disc. */
	private static final long SHEET_LIMIT = 1 << 20;

	/** The sheet of the disc this program came from, or null when it is not a disc. */
	static String sheetOf(Program program) {
		if (program == null || !isDisc(program) || program.getExecutablePath() == null) {
			return null;
		}

		File imported = new File(program.getExecutablePath());
		if (isSheet(imported)) {
			return imported.getAbsolutePath();
		}

		File directory = imported.getParentFile();
		File[] sheets = directory == null ? null : directory.listFiles(DiscSheet::isSheet);
		if (sheets == null) {
			return null;
		}
		for (File sheet : sheets) {
			if (namesDump(sheet, imported.getName())) {
				return sheet.getAbsolutePath();
			}
		}
		return null;
	}

	/**
	 * True when two files describe one disc: they are the same file, or one of them is the sheet
	 * that names the dump the other is.
	 */
	static boolean sameDisc(String first, String second) {
		if (first == null || second == null) {
			return false;
		}
		File one = new File(first);
		File other = new File(second);
		if (one.getAbsolutePath().equals(other.getAbsolutePath())) {
			return true;
		}
		return isSheet(other) && namesDump(other, one.getName())
				|| isSheet(one) && namesDump(one, other.getName());
	}

	static boolean isDisc(Program program) {
		String format = program == null ? null : program.getExecutableFormat();
		return SegaCdMainLoader.LOADER_NAME.equals(format)
				|| SegaCdSubLoader.LOADER_NAME.equals(format)
				// A file of the volume came off this disc as much as the program its header declares,
				// and it is the sheet that has to be handed to the emulator for it.
				|| SegaCdMmdLoader.LOADER_NAME.equals(format);
	}

	/**
	 * The log BlastEm writes the addresses of the processor this program stands for. Reading the
	 * other one would fill the listing with the blocks of a different CPU and call them code of this
	 * program's, which nothing else here would ever notice.
	 */
	static String traceNameOf(Program program) {
		return SegaCdSubLoader.LOADER_NAME.equals(
			program == null ? null : program.getExecutableFormat()) ? DRIVE_TRACE : CONSOLE_TRACE;
	}

	/**
	 * Why the emulator is left alone with that image, or null when the panel may run it. A sheet that
	 * hands the disc out in several files is a rip laid down for a burner: every track sits in a file of
	 * its own, one of them carrying the program Ghidra read and the rest nothing to execute, and the
	 * drive of the emulator then plays the whole disc. Such a sheet does start — it was run by hand — but
	 * a session of it is the disc rather than that program, so the panel keeps out and asks for the
	 * single image of the data track instead.
	 */
	static String refusalFor(String image) {
		if (image == null || image.isBlank()) {
			return null;
		}
		File file = new File(image);
		if (!isSheet(file)) {
			return null;
		}

		int named = filesNamed(file);
		return named < 2 ? null : String.format(
			"the sheet %s hands the disc over %d files, and the panel does not start BlastEm for a "
				+ "disc laid out that way. Sega CD support here is experimental: take the disc to a "
				+ "single image of its data track, an .iso, point the ROM field at it and import that "
				+ "file to have a session of the panel. A trace made elsewhere still comes in "
				+ "through Ingest log...", file.getName(), named);
	}

	private static boolean isSheet(File file) {
		return file.isFile() && file.getName().toLowerCase().endsWith(".cue");
	}

	/** The dumps a sheet names, counted once however many of its tracks share one. */
	private static int filesNamed(File sheet) {
		String text = textOf(sheet);
		if (text == null) {
			return 0;
		}

		Set<String> names = new LinkedHashSet<>();
		for (String line : text.split("\\R")) {
			String name = namedFile(line.trim());
			if (name != null) {
				names.add(name);
			}
		}
		return names.size();
	}

	/** Whether the sheet hands a track to the dump of that name. */
	private static boolean namesDump(File sheet, String dumpName) {
		String text = textOf(sheet);
		if (text == null) {
			return false;
		}

		for (String line : text.split("\\R")) {
			if (dumpName.equals(namedFile(line.trim()))) {
				return true;
			}
		}
		return false;
	}

	/** The dump a `FILE` line names, or null when the line is not one of them. */
	private static String namedFile(String entry) {
		if (!entry.regionMatches(true, 0, "FILE", 0, 4) || entry.length() < 5
				|| !Character.isWhitespace(entry.charAt(4))) {
			return null;
		}
		String name = entry.indexOf('"') >= 0 ? quoted(entry) : bareName(entry);
		return name.isEmpty() ? null : name;
	}

	/** The words of a sheet, or null when they cannot be read at all. */
	private static String textOf(File sheet) {
		if (sheet.length() > SHEET_LIMIT) {
			return null;
		}
		try {
			return new String(Files.readAllBytes(sheet.toPath()), StandardCharsets.ISO_8859_1);
		}
		catch (IOException e) {
			return null;
		}
	}

	/** The name between the quotes of a line, which carries spaces and parentheses alike. */
	private static String quoted(String entry) {
		int first = entry.indexOf('"');
		int last = entry.lastIndexOf('"');
		return first >= 0 && last > first ? entry.substring(first + 1, last) : "";
	}

	/** The name of a line that did not quote it, which is the second word of it. */
	private static String bareName(String entry) {
		String[] words = entry.substring(4).trim().split("\\s+");
		return words.length < 2 ? "" : words[0];
	}
}

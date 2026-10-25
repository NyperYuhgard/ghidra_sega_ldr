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
import java.util.function.Predicate;

import ghidra.app.util.importer.MessageLog;

/**
 * The files of a disc. A Sega CD disc is an ISO-9660 volume as well as a header sector, and the
 * things a game asks the drive for live inside it under names: a disc hands a program a name and
 * never a place in memory, so reaching one of those files is the only way to know it is there.
 */
class CdIso {

	/** One file, or one directory, as the volume names it and where its bytes begin. */
	record Entry(String path, long sector, long size, boolean directory, boolean scattered) {
	}

	/** A volume always puts its descriptors at the same place, sixteen sectors past the lead-in. */
	private static final int FIRST_DESCRIPTOR_SECTOR = 16;

	/** A disc that goes that many sectors without saying what volume it is, is not one. */
	private static final int DESCRIPTOR_SEARCH_SECTORS = 32;

	private static final int SECTOR = 2048;

	/** A directory is read no further than this, however large it says it is. */
	private static final int MAX_DIRECTORY_BYTES = 512 * SECTOR;

	/** Past this, a file of a disc is data, and Ghidra is not where data wants to live. */
	static final int READ_LIMIT = 1 << 20;

	private static final int MAX_ENTRIES_OF_A_DIRECTORY = 2048;
	private static final int MAX_ENTRIES = 8192;
	private static final int MAX_DIRECTORIES = 64;
	private static final int MAX_DEPTH = 8;

	private final CdImage disc;
	private final MessageLog log;
	private final String systemId;
	private final String volumeId;
	private final long rootSector;
	private final long rootBytes;

	private final List<Entry> entries = new ArrayList<>();
	private final List<String> notes = new ArrayList<>();

	private int directories;
	private int scattered;
	private int writtenTwice;
	private int foreignNames;
	private boolean oneByteNames;
	private boolean capped;

	private CdIso(CdImage disc, MessageLog log, byte[] descriptor) {
		this.disc = disc;
		this.log = log;
		this.systemId = spaced(descriptor, 8, 32);
		this.volumeId = spaced(descriptor, 40, 32);
		// The root of a volume is a directory record kept inside its own descriptor.
		this.rootSector = le32(descriptor, 158);
		this.rootBytes = le32(descriptor, 166);
	}

	/**
	 * The volume of the disc, or null when it carries none. A disc whose tracks are not a volume of
	 * stored sectors is not a mistake of the import, so it is said of it what is said of a disc with
	 * no files on it: nothing is placed, and nothing is refused.
	 */
	static CdIso open(CdImage disc, MessageLog log) throws IOException {
		byte[] descriptor = primaryDescriptor(disc, log);
		if (descriptor == null) {
			return null;
		}

		int block = le16(descriptor, 128);
		if (block != SECTOR) {
			log.appendMsg(String.format(
				"the volume of the disc reads blocks of %d byte(s), which cannot be served sector by sector",
				block));
			return null;
		}

		CdIso iso = new CdIso(disc, log, descriptor);
		if (be16(descriptor, 130) != SECTOR) {
			iso.notes.add(String.format(
				"the volume writes its block size twice and the two do not agree (0x%X and 0x%X); the little endian writing is followed",
				block, be16(descriptor, 130)));
		}

		long sectors = le32(descriptor, 80);
		if (sectors > disc.sectors()) {
			iso.notes.add(String.format(
				"the volume counts %d sector(s) and the disc holds %d, so whatever the volume puts past them is not read",
				sectors, disc.sectors()));
		}

		iso.walk(iso.rootSector, iso.rootBytes, "", 0);
		return iso;
	}

	/**
	 * The descriptor that says what system a volume is made for, looked for where a volume puts its
	 * descriptors and nowhere else.
	 */
	private static byte[] primaryDescriptor(CdImage disc, MessageLog log) throws IOException {
		if (disc.sectors() <= FIRST_DESCRIPTOR_SECTOR) {
			log.appendMsg(String.format(
				"the disc holds %d sector(s), which never reaches the sector 16 where a volume puts its descriptors: its files cannot be listed",
				disc.sectors()));
			return null;
		}

		long last = Math.min(FIRST_DESCRIPTOR_SECTOR + DESCRIPTOR_SEARCH_SECTORS, disc.sectors());
		boolean supplementary = false;

		for (long sector = FIRST_DESCRIPTOR_SECTOR; sector < last; sector++) {
			byte[] block = disc.readUserData(sector * SECTOR, SECTOR);
			if (block.length < SECTOR || !"CD001".equals(spaced(block, 1, 5))) {
				continue;
			}

			int type = block[0] & 0xff;
			if (type == 255) {
				log.appendMsg(String.format(
					"the descriptors of the disc end at sector %d, before any of them says what volume it is: its files cannot be listed",
					sector));
				return null;
			}
			if (type == 1) {
				return block;
			}
			if (type == 2 && !supplementary) {
				supplementary = true;
				log.appendMsg(String.format(
					"sector %d holds a supplementary volume descriptor, which a program reaches only through the primary one that is missing here",
					sector));
			}
		}

		log.appendMsg(String.format(
			"nothing between sectors %d and %d is a volume descriptor, so the files of the disc cannot be listed",
			FIRST_DESCRIPTOR_SECTOR, last - 1));
		return null;
	}

	/**
	 * The records of one directory: a run of entries of variable length whose end is told by a
	 * length of zero standing for a record that goes on past the sector. Nothing of a volume is
	 * trusted further than a record that looks like one, because a directory that stops writing its
	 * records before the size it declares would otherwise walk into the bytes of the file that
	 * follows them.
	 */
	private void walk(long sector, long declared, String prefix, int depth) throws IOException {
		String name = prefix.isEmpty() ? "the root of the volume" : "the directory " + prefix;

		if (directories >= MAX_DIRECTORIES) {
			capped = true;
			return;
		}
		if (depth > MAX_DEPTH) {
			note("%s is nested deeper than %d directories, and is not read", name, MAX_DEPTH);
			return;
		}
		if (sector < 0 || sector >= disc.sectors()) {
			note("%s is put at sector %d, which the disc does not reach", name, sector);
			return;
		}
		directories++;

		long room = (disc.sectors() - sector) * SECTOR;
		int bytes = (int) Math.min(Math.min(declared, MAX_DIRECTORY_BYTES), room);
		if (declared > bytes) {
			note("%s says %d byte(s) of itself and %d are read", name, declared, bytes);
		}

		byte[] block = disc.readUserData(sector * SECTOR, bytes);
		int counted = 0;
		int at = 0;
		while (at < block.length) {
			if ((block[at] & 0xff) == 0) {
				int next = (at / SECTOR + 1) * SECTOR;
				if (next >= block.length || recordAt(block, next) == null) {
					note("the records of %s end at byte %d of the %d it declares", name, at,
						declared);
					return;
				}
				at = next;
			}

			Record record = recordAt(block, at);
			if (record == null) {
				note("the records of %s stop at byte %d, which does not open as one", name, at);
				return;
			}
			at += record.length;

			if (record.dot) {
				continue;
			}
			if (++counted > MAX_ENTRIES_OF_A_DIRECTORY || entries.size() >= MAX_ENTRIES) {
				capped = true;
				return;
			}

			String path = prefix + record.name;
			entries.add(new Entry(path, record.extent, record.size, record.directory,
				record.scattered));
			if (record.scattered) {
				scattered++;
			}
			if (record.directory) {
				walk(record.extent, record.size, path + "/", depth + 1);
			}
		}
	}

	/** One directory record, or null when the bytes at that place are not one. */
	private Record recordAt(byte[] block, int at) {
		int length = block[at] & 0xff;
		if (length < 34 || at + length > block.length) {
			return null;
		}

		long extent = le32(block, at + 2);
		long size = le32(block, at + 10);
		if (extent < 0 || extent + (size + SECTOR - 1) / SECTOR > disc.sectors()) {
			return null;
		}
		if (be32(block, at + 6) != extent || be32(block, at + 14) != size) {
			writtenTwice++;
		}

		// A name is a length and the bytes of it. The standard asks for the length as two words of
		// sixteen and the name at forty; the discs of Sega write one byte at thirty two and the name
		// at thirty three. Either is read, and which one a volume used is said once.
		int nameAt = at + 40;
		int nameLength = le16(block, at + 36);
		if (nameLength < 1 || nameAt + nameLength > at + length) {
			nameAt = at + 33;
			nameLength = block[at + 32] & 0xff;
			if (nameLength < 1 || nameAt + nameLength > at + length) {
				return null;
			}
			oneByteNames = true;
		}

		// A directory begins with two records for itself and the one above it, named with one byte
		// that is not a letter at all.
		if (nameLength == 1 && (block[nameAt] & 0xff) < 2) {
			return new Record(length, extent, size, true, false, false, "");
		}

		byte[] raw = new byte[nameLength];
		System.arraycopy(block, nameAt, raw, 0, nameLength);
		String name = identifier(raw);
		if (name == null) {
			return null;
		}

		int flags = block[at + 25] & 0xff;
		return new Record(length, extent, size, false, (flags & 1) != 0, (flags & 2) != 0, name);
	}

	/**
	 * The identifier of a record with the version the volume puts after a semicolon left off, or
	 * null when the bytes of it are not a name at all. A name that is not of this standard — the
	 * escapes a volume of another one writes in two byte characters — is kept as it reads and
	 * counted, because its letters are the only thing that will say what it is.
	 */
	private String identifier(byte[] raw) {
		StringBuilder name = new StringBuilder(raw.length);
		for (byte b : raw) {
			int c = b & 0xff;
			if (c < ' ' || c > '~') {
				return null;
			}
			name.append((char) c);
		}

		String text = name.toString();
		int semicolon = text.lastIndexOf(';');
		if (semicolon >= 0) {
			text = text.substring(0, semicolon);
		}
		if (text.isEmpty() || !text.matches("[A-Z0-9._\\-]+")) {
			foreignNames++;
		}
		return text.isEmpty() ? null : text;
	}

	/** The files of the volume, named all of them: what a disc holds is what its import has to say. */
	void logEntries() {
		log.appendMsg(String.format(
			"ISO-9660 volume '%s' / '%s', root at sector %d: %d file(s), %d of them directories",
			systemId, volumeId, rootSector, files(), entries.size() - files()));

		for (Entry entry : entries) {
			log.appendMsg(String.format("  %s  sector %d  %d byte(s)%s", entry.path(),
				entry.sector(), entry.size(), entry.directory() ? " (directory)" : ""));
		}

		if (oneByteNames) {
			log.appendMsg(
				"the volume writes the length of a name as one byte at 32 instead of two at 36; the records of it are read either way");
		}
		if (scattered > 0) {
			log.appendMsg(String.format(
				"%d entry(ies) are written over more than one extent, so their bytes are not in one run of the disc",
				scattered));
		}
		if (writtenTwice > 0) {
			log.appendMsg(String.format(
				"%d record(s) are written twice over, the second time a different way; the little endian writing is followed",
				writtenTwice));
		}
		if (foreignNames > 0) {
			log.appendMsg(String.format(
				"%d name(s) of the volume are not of this standard, and are listed as they read",
				foreignNames));
		}
		if (capped) {
			log.appendMsg(String.format(
				"the tree is deeper or wider than %d file(s) in %d directories, and what comes after is not listed",
				MAX_ENTRIES, MAX_DIRECTORIES));
		}
		for (String note : notes) {
			log.appendMsg(note);
		}
	}

	/**
	 * The entries a name given to the importer stands for, which is more than one when a volume keeps
	 * the same name in two directories. The version, the extension and the directory of a file are
	 * all things a person leaves out of what they type, so all three are accepted — and leaving the
	 * extension off is only taken when it cannot be mistaken for another file.
	 */
	List<Entry> find(String wanted) {
		return byName(wanted.toUpperCase().replace('\\', '/'));
	}

	private List<Entry> byName(String given) {
		int semicolon = given.lastIndexOf(';');
		final String needle = semicolon < 0 ? given : given.substring(0, semicolon);

		List<Entry> found = matching(entry -> entry.path().equals(needle));
		if (!found.isEmpty()) {
			return found;
		}
		found = matching(entry -> stem(entry.path()).equals(needle));
		if (!found.isEmpty()) {
			return found;
		}
		found = matching(entry -> leaf(entry.path()).equals(needle));
		if (!found.isEmpty()) {
			return found;
		}
		return matching(entry -> stem(leaf(entry.path())).equals(stem(needle)));
	}

	private List<Entry> matching(Predicate<Entry> test) {
		List<Entry> found = new ArrayList<>();
		for (Entry entry : entries) {
			if (test.test(entry)) {
				found.add(entry);
			}
		}
		return found;
	}

	/** The bytes of one entry, up to the limit a member of a disc is given. */
	byte[] read(Entry entry) throws IOException {
		long wanted = Math.min(entry.size(), READ_LIMIT);

		if (entry.scattered()) {
			log.appendMsg(String.format(
				"%s is written over more than one extent, so the bytes that follow its first one are given, and they are not the whole of the file",
				entry.path()));
		}

		byte[] data = disc.readUserData(entry.sector() * SECTOR, (int) wanted);
		if (entry.size() > wanted) {
			log.appendMsg(String.format(
				"%s holds %d byte(s), and %d are read: the limit of a member of a disc is 1 MiB, so %d byte(s) are left out",
				entry.path(), entry.size(), data.length, entry.size() - wanted));
		}
		if (data.length < wanted) {
			log.appendMsg(String.format(
				"%s is put at sector %d for %d byte(s), and the disc serves only %d", entry.path(),
				entry.sector(), wanted, data.length));
		}

		return data;
	}

	List<Entry> entries() {
		return List.copyOf(entries);
	}

	String systemId() {
		return systemId;
	}

	String volumeId() {
		return volumeId;
	}

	/** What the volume holds, one line each, for a message that has to name what was asked for. */
	String listPaths() {
		StringBuilder list = new StringBuilder();
		for (Entry entry : entries) {
			list.append(list.isEmpty() ? "" : ", ").append(entry.path());
		}
		return list.toString();
	}

	private long files() {
		long count = 0;
		for (Entry entry : entries) {
			if (!entry.directory()) {
				count++;
			}
		}
		return count;
	}

	private void note(String format, Object... arguments) {
		notes.add(String.format(format, arguments));
	}

	private static String leaf(String path) {
		return path.substring(path.lastIndexOf('/') + 1);
	}

	private static String stem(String path) {
		return path.substring(0, Math.max(path.lastIndexOf('.'), 0));
	}

	private static int le16(byte[] data, int at) {
		return (data[at] & 0xff) | (data[at + 1] & 0xff) << 8;
	}

	private static int be16(byte[] data, int at) {
		return (data[at] & 0xff) << 8 | (data[at + 1] & 0xff);
	}

	private static long le32(byte[] data, int at) {
		return (data[at] & 0xffL) | (data[at + 1] & 0xffL) << 8 | (data[at + 2] & 0xffL) << 16
				| (data[at + 3] & 0xffL) << 24;
	}

	private static long be32(byte[] data, int at) {
		return (data[at] & 0xffL) << 24 | (data[at + 1] & 0xffL) << 16
				| (data[at + 2] & 0xffL) << 8 | (data[at + 3] & 0xffL);
	}

	/** The letters of a field of a descriptor, with the space a short one is padded with left off. */
	private static String spaced(byte[] data, int at, int length) {
		StringBuilder text = new StringBuilder(length);
		for (int i = 0; i < length && at + i < data.length; i++) {
			char c = (char) (data[at + i] & 0xff);
			if (c != ' ' && c != 0) {
				text.append(c);
			}
		}
		return text.toString();
	}

	/** What a record of a directory says. */
	private static class Record {

		private final int length;
		private final long extent;
		private final long size;
		private final boolean dot;
		private final boolean scattered;
		private final boolean directory;
		private final String name;

		Record(int length, long extent, long size, boolean dot, boolean scattered,
				boolean directory, String name) {

			this.length = length;
			this.extent = extent;
			this.size = size;
			this.dot = dot;
			this.scattered = scattered;
			this.directory = directory;
			this.name = name;
		}
	}
}

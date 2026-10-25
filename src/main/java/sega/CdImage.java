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

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessMode;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.FileByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.util.Msg;

/**
 * The data track of a Sega CD disc, seen as the console sees it: a run of sectors whose user data
 * the BIOS reads from. A disc arrives either as the sector dump itself, or as the sheet that
 * describes it, whose tracks name the dumps to read and the sector each one begins on.
 */
class CdImage {

	static final String SIGNATURE = "SEGADISCSYSTEM";

	/** The two layouts a data track can have; the sync and header of a raw sector are 16 bytes. */
	private static final int SECTOR_USER_DATA = 2048;
	private static final int SECTOR_WITH_SYNC = 2352;
	private static final int SYNC_SIZE = 16;

	/** How far the head of a dump is searched for the start of the track. */
	private static final int TRACK_SEARCH_SECTORS = 64;

	/** A sheet is a few hundred lines of text; nothing that long is describing a disc. */
	private static final int SHEET_LIMIT = 1 << 20;

	private final ByteProvider provider;

	/** The dump of a sheet is opened here, so it is also closed here. */
	private final boolean ownsProvider;
	private final MessageLog log;

	/** Byte offset of the first sector of the data track within the file. */
	private final long trackStart;

	/** Bytes of one sector as stored, and the skip that reaches its user data. */
	private final int sectorBytes;
	private final int skip;

	/** How much user data the file can still serve from the start of the track. */
	private final long userDataBytes;

	/** The sheet whose line named this dump, and how it divides the disc. */
	private final String sheetName;
	private final String sheetLayout;

	private CdImage(ByteProvider provider, boolean ownsProvider, MessageLog log, long trackStart,
			int sectorBytes, long fileLength, String sheetName, String sheetLayout) {

		this.provider = provider;
		this.ownsProvider = ownsProvider;
		this.log = log;
		this.trackStart = trackStart;
		this.sectorBytes = sectorBytes;
		this.skip = sectorBytes == SECTOR_WITH_SYNC ? SYNC_SIZE : 0;
		// The framing of a raw sector sits in front of its user data, so a track of whole sectors
		// still serves all of them.
		this.userDataBytes =
			Math.max(0, (fileLength - trackStart) / sectorBytes) * SECTOR_USER_DATA;
		this.sheetName = sheetName;
		this.sheetLayout = sheetLayout;
	}

	/**
	 * The layout of the disc the importer opened, or null when neither its bytes nor the dumps its
	 * sheet points at carry a Sega CD signature.
	 */
	static CdImage open(ByteProvider provider, MessageLog log) throws IOException {
		BinaryReader reader = new BinaryReader(provider, true);

		Sector own = findTrack(reader, 0, 0);
		if (own != null) {
			return new CdImage(provider, false, log, own.start(), own.sectorBytes(),
				provider.length(), null, null);
		}

		Sheet sheet = Sheet.read(reader, provider.getName());
		if (sheet == null) {
			return null;
		}

		String path = provider.getAbsolutePath();
		if (path == null) {
			// A sheet that was not opened from the disk cannot say where its dumps are.
			log.appendMsg(String.format("%s has no folder of its own, so the dumps it names "
				+ "cannot be found", sheet.name));
			return null;
		}
		File directory = new File(path).getParentFile();

		for (Track track : sheet.dataTracks()) {
			File file = new File(directory, track.fileName);
			if (!file.isFile()) {
				// Nothing else ever says why a sheet was turned down, and the importer will not
				// look at the reason: by then the file simply has no loader.
				Msg.error(CdImage.class, String.format(
					"the sheet %s puts track %s in %s, which is not in %s", sheet.name,
					track.number, file.getName(), directory));
				continue;
			}

			ByteProvider dump = new FileByteProvider(file, null, AccessMode.READ);
			long declaredStart = Math.max(0, track.startFrame) * track.sectorBytes;
			Sector sector =
				findTrack(new BinaryReader(dump, true), declaredStart, track.sectorBytes);
			if (sector == null) {
				dump.close();
				continue;
			}
			if (sector.start() != declaredStart) {
				// The sheet numbers its tracks somewhere the bytes do not agree with, and the
				// signature is the only thing here that says where the program actually begins.
				log.appendMsg(String.format(
					"%s says track %s of %s starts at sector %d, its SEGADISCSYSTEM sector is at %d",
					sheet.name, track.number, file.getName(), declaredStart / track.sectorBytes,
					sector.start() / sector.sectorBytes));
			}
			return new CdImage(dump, true, log, sector.start(), sector.sectorBytes(),
				file.length(), sheet.name, sheet.layout());
		}

		return null;
	}

	/**
	 * The sector of a dump where a data track begins, and the size that frames it, or null when the
	 * dump carries no signature. Where the sheet puts the track is tried first; the search past that
	 * covers a rip that keeps the pregap sectors of a track in front of it, and a sheet that numbers
	 * its tracks against the whole disc while giving each one its own file.
	 */
	private static Sector findTrack(BinaryReader reader, long declaredStart, int declaredBytes)
			throws IOException {

		if (declaredBytes > 0) {
			Sector declared = framingAt(reader, declaredStart, declaredBytes);
			if (declared != null) {
				return declared;
			}
		}
		for (int sectorBytes : new int[] { SECTOR_WITH_SYNC, SECTOR_USER_DATA }) {
			for (int index = 0; index < TRACK_SEARCH_SECTORS; index++) {
				Sector found = framingAt(reader, (long) index * sectorBytes, sectorBytes);
				if (found != null) {
					return found;
				}
			}
		}
		return null;
	}

	/** The framing that puts the signature inside the sector beginning at the given position. */
	private static Sector framingAt(BinaryReader reader, long start, int sectorBytes)
			throws IOException {

		long at = start + (sectorBytes == SECTOR_WITH_SYNC ? SYNC_SIZE : 0);
		if (at >= 0 && at + SIGNATURE.length() <= reader.length()
				&& SIGNATURE.equals(reader.readAsciiString(at, SIGNATURE.length()))) {
			return new Sector(start, sectorBytes);
		}
		return null;
	}

	/** Where a track begins in a dump, and how wide its sectors are. */
	private record Sector(long start, int sectorBytes) {
	}

	/**
	 * The bytes a read of the console would return for an offset counted in user data, which is how
	 * the disc header names the places its programs sit on the disc.
	 */
	byte[] readUserData(long offset, int length) throws IOException {
		if (offset < 0) {
			return new byte[0];
		}

		long available = Math.min(length, userDataBytes - offset);
		if (available <= 0) {
			return new byte[0];
		}
		if (available < length) {
			log.appendMsg(String.format(
				"asked for 0x%X program byte(s) at disc offset 0x%X, the disc serves only 0x%X",
				length, offset, available));
		}

		byte[] data = new byte[(int) available];
		int done = 0;
		while (done < available) {
			long position = offset + done;
			int within = (int) (position % SECTOR_USER_DATA);
			int chunk = (int) Math.min(available - done, SECTOR_USER_DATA - within);

			long fileOffset =
				trackStart + position / SECTOR_USER_DATA * sectorBytes + skip + within;
			System.arraycopy(provider.readBytes(fileOffset, chunk), 0, data, done, chunk);
			done += chunk;
		}

		return data;
	}

	/** Bytes of user data the track can serve from its first sector. */
	long userDataBytes() {
		return userDataBytes;
	}

	/** Sectors of the track that carry data a processor can be given. */
	long sectors() {
		return userDataBytes / SECTOR_USER_DATA;
	}

	int sectorBytes() {
		return sectorBytes;
	}

	long trackStart() {
		return trackStart;
	}

	String getFileName() {
		return provider.getName();
	}

	/** The sheet this track was found through, or null when the file opened is the dump itself. */
	String sheetName() {
		return sheetName;
	}

	/** How the sheet divides the disc, as one line. */
	String sheetLayout() {
		return sheetLayout;
	}

	void close() throws IOException {
		if (ownsProvider) {
			provider.close();
		}
	}

	/**
	 * The sheet that describes a disc. Its keywords name the dumps its tracks live in and the sector
	 * each one starts on; the sheet may open with anything the ripper wrote first — a catalog number,
	 * a comment, the generation date — so it is recognized by carrying a FILE and a TRACK rather
	 * than by its first word.
	 */
	private static class Sheet {

		private final String name;
		private final List<Track> tracks;
		private final int files;
		private final int unreadable;

		private Sheet(String name, List<Track> tracks, int files, int unreadable) {
			this.name = name;
			this.tracks = tracks;
			this.files = files;
			this.unreadable = unreadable;
		}

		/** The sheet written in those bytes, or null when they are not one. */
		static Sheet read(BinaryReader reader, String path) throws IOException {
			String text = textOf(reader);
			if (text == null) {
				return null;
			}

			List<Track> tracks = new ArrayList<>();
			Set<String> files = new HashSet<>();
			String fileName = null;
			String format = null;
			int unreadable = 0;

			for (String line : text.split("\\R")) {
				List<String> entry = words(line);
				if (entry.isEmpty()) {
					continue;
				}

				switch (entry.get(0).toUpperCase()) {
					case "FILE":
						fileName = entry.size() > 1 ? entry.get(1) : null;
						format = entry.size() > 2 ? entry.get(2) : null;
						if (fileName != null && files.add(fileName) && !isByteDump(format)) {
							unreadable++;
						}
						break;
					case "TRACK":
						tracks.add(Track.parse(fileName, format, entry));
						break;
					case "INDEX":
						if (!tracks.isEmpty()) {
							tracks.get(tracks.size() - 1).addIndex(entry);
						}
						break;
					default:
						// CATALOG, REM, GENRE, DATE, FLAGS, PREGAP, POSTGAP and ISRC tell a burner
						// how to lay the disc down and give a program nothing.
						break;
				}
			}

			if (files.isEmpty() || tracks.isEmpty()) {
				return null;
			}
			return new Sheet(nameOf(path), tracks, files.size(), unreadable);
		}

		/** The text of a sheet, or null when the bytes are not text at all. */
		private static String textOf(BinaryReader reader) throws IOException {
			if (reader.length() < 16 || reader.length() > SHEET_LIMIT) {
				return null;
			}
			byte[] bytes = reader.readByteArray(0, (int) reader.length());
			for (byte b : bytes) {
				if (b == 0) {
					return null;
				}
			}
			String text = new String(bytes, StandardCharsets.ISO_8859_1);
			return text.startsWith("\uFEFF") ? text.substring(1) : text;
		}

		/**
		 * The words of a line, with a quoted run kept whole: the rips that give every track its own
		 * file name it after the title of the game, spaces and parentheses and all.
		 */
		private static List<String> words(String line) {
			List<String> entry = new ArrayList<>();
			StringBuilder current = new StringBuilder();
			char quote = 0;
			for (int i = 0; i < line.length(); i++) {
				char c = line.charAt(i);
				if (quote != 0) {
					if (c == quote) {
						quote = 0;
					}
					else {
						current.append(c);
					}
				}
				else if (c == '"' || c == '\'') {
					quote = c;
				}
				else if (Character.isWhitespace(c)) {
					if (current.length() > 0) {
						entry.add(current.toString());
						current.setLength(0);
					}
				}
				else {
					current.append(c);
				}
			}
			if (current.length() > 0) {
				entry.add(current.toString());
			}
			return entry;
		}

		/** A dump of stored bytes, which is the only kind a sector can be counted in. */
		static boolean isByteDump(String format) {
			return format == null || format.isEmpty() || "BINARY".equalsIgnoreCase(format);
		}

		private static String nameOf(String path) {
			return path == null ? "the sheet" : new File(path).getName();
		}

		List<Track> dataTracks() {
			List<Track> data = new ArrayList<>();
			for (Track track : tracks) {
				if (track.isData()) {
					data.add(track);
				}
			}
			return data;
		}

		String layout() {
			int programs = dataTracks().size();
			String text = String.format(
				"%d track(s) in %d file(s), %d of them carrying a program", tracks.size(), files,
				programs);
			if (tracks.size() > programs) {
				text += String.format(" and %d that cannot hold one", tracks.size() - programs);
			}
			if (unreadable > 0) {
				text += String.format(", %d named in a format that is not a dump of bytes",
					unreadable);
			}
			return text;
		}
	}

	/** One entry of a sheet: which file holds it, how large its sectors are, where it begins. */
	private static class Track {

		private final String fileName;
		private final String format;
		private final String number;
		private final int sectorBytes;
		private long startFrame = -1;

		private Track(String fileName, String format, String number, int sectorBytes) {
			this.fileName = fileName;
			this.format = format;
			this.number = number;
			this.sectorBytes = sectorBytes;
		}

		static Track parse(String fileName, String format, List<String> entry) {
			// TRACK 01 MODE1/2352: only a MODE1 track can carry a program, and the number after the
			// slash is what says how wide its sectors are. An AUDIO track gives nothing to execute.
			String type = entry.size() > 2 ? entry.get(2) : "";
			int slash = type.indexOf('/');
			int size = slash < 0 ? 0 : toInt(type.substring(slash + 1));
			return new Track(fileName, format, entry.size() > 1 ? entry.get(1) : "?", size);
		}

		void addIndex(List<String> entry) {
			if (entry.size() < 3 || !"01".equals(entry.get(1)) || startFrame >= 0) {
				return;
			}
			String[] clock = entry.get(2).split(":");
			if (clock.length != 3) {
				return;
			}
			long minutes = toInt(clock[0]);
			long seconds = toInt(clock[1]);
			long frames = toInt(clock[2]);
			if (minutes < 0 || seconds < 0 || frames < 0) {
				return;
			}
			startFrame = minutes * 60 * 75 + seconds * 75 + frames;
		}

		boolean isData() {
			return fileName != null && Sheet.isByteDump(format)
				&& (sectorBytes == SECTOR_USER_DATA || sectorBytes == SECTOR_WITH_SYNC);
		}

		private static int toInt(String value) {
			try {
				return Integer.parseInt(value);
			}
			catch (NumberFormatException e) {
				return -1;
			}
		}
	}
}

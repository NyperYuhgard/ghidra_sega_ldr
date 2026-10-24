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
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.FileByteProvider;
import ghidra.app.util.importer.MessageLog;

/**
 * The first data track of a Sega CD disc, seen as the console sees it: a run of sectors whose user
 * data the BIOS reads from. A disc arrives either as the sector dump itself, where the signature
 * tells the sector size, or as the sheet that describes it, whose first data track points at the
 * dump and at the sector the program area starts on.
 */
class CdImage {

	static final String SIGNATURE = "SEGADISCSYSTEM";

	/** The two layouts a data track can have; the sync and header of a raw sector are 16 bytes. */
	private static final int SECTOR_USER_DATA = 2048;
	private static final int SECTOR_WITH_SYNC = 2352;

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

	private CdImage(ByteProvider provider, boolean ownsProvider, MessageLog log, long trackStart,
			int sectorBytes, long fileLength) {

		this.provider = provider;
		this.ownsProvider = ownsProvider;
		this.log = log;
		this.trackStart = trackStart;
		this.sectorBytes = sectorBytes;
		this.skip = sectorBytes == SECTOR_WITH_SYNC ? 16 : 0;
		this.userDataBytes =
			Math.max(0, (fileLength - trackStart - skip) / sectorBytes * SECTOR_USER_DATA);
	}

	/**
	 * The layout of the disc the importer opened, or null when neither its bytes nor the dump its
	 * sheet points at carry a Sega CD signature.
	 */
	static CdImage open(ByteProvider provider, MessageLog log) throws IOException {
		BinaryReader reader = new BinaryReader(provider, true);

		long rawOffset = signatureOffset(reader);
		if (rawOffset >= 0) {
			int sectorBytes = rawOffset == 0 ? SECTOR_USER_DATA : SECTOR_WITH_SYNC;
			return new CdImage(provider, false, log, 0, sectorBytes, provider.length());
		}

		if (!isCueSheet(reader)) {
			return null;
		}

		File directory = new File(provider.getAbsolutePath()).getParentFile();
		for (Track track : parseCue(provider)) {
			File file = new File(directory, track.fileName);
			if (!file.isFile()) {
				continue;
			}

			ByteProvider dump = new FileByteProvider(file, null, AccessMode.READ);
			long offset = signatureOffset(new BinaryReader(dump, true));
			if (offset < 0) {
				dump.close();
				continue;
			}

			// The sheet, not the bytes, is what says how large a sector of this dump is.
			int sectorBytes = track.sectorBytes != 0 ? track.sectorBytes
				: (offset == 0 ? SECTOR_USER_DATA : SECTOR_WITH_SYNC);
			return new CdImage(dump, true, log, track.startFrame * sectorBytes, sectorBytes,
				file.length());
		}

		return null;
	}

	/** Byte offset of the signature inside a sector dump, or -1 when there is none. */
	static long signatureOffset(BinaryReader reader) throws IOException {
		if (reader.length() < SECTOR_USER_DATA) {
			return -1;
		}
		if (SIGNATURE.equals(reader.readAsciiString(0, SIGNATURE.length()))) {
			return 0;
		}
		if (reader.length() >= SECTOR_WITH_SYNC
				&& SIGNATURE.equals(reader.readAsciiString(16, SIGNATURE.length()))) {
			return 16;
		}
		return -1;
	}

	private static boolean isCueSheet(BinaryReader reader) throws IOException {
		return reader.length() >= 6 && "FILE \"".equals(reader.readAsciiString(0, 6));
	}

	/**
	 * The data tracks of a sheet, in the order they are listed. Only MODE1 tracks can carry a
	 * program, and the sheets of these consoles describe every track with the same three keywords.
	 */
	private static List<Track> parseCue(ByteProvider provider) throws IOException {
		String text = new String(provider.readBytes(0, provider.length()),
			StandardCharsets.ISO_8859_1);
		List<Track> tracks = new ArrayList<>();
		String fileName = null;

		for (String line : text.split("\\R")) {
			String[] words = line.trim().split("\\s+");
			if (words.length < 2) {
				continue;
			}

			switch (words[0].toUpperCase()) {
				case "FILE":
					fileName = unquote(words[1]);
					break;
				case "TRACK":
					tracks.add(Track.parse(fileName, words));
					break;
				case "INDEX":
					if (!tracks.isEmpty()) {
						tracks.get(tracks.size() - 1).addIndex(words);
					}
					break;
				default:
					break;
			}
		}

		tracks.removeIf(track -> !track.isData());
		return tracks;
	}

	private static String unquote(String value) {
		int first = value.indexOf('"');
		int last = value.lastIndexOf('"');
		return first >= 0 && last > first ? value.substring(first + 1, last) : value;
	}

	/** One entry of a sheet: which file holds it, how large its sectors are, where it begins. */
	private static class Track {

		private final String fileName;
		private final boolean mode1;
		private final int sectorBytes;
		private long startFrame = -1;

		private Track(String fileName, boolean mode1, int sectorBytes) {
			this.fileName = fileName;
			this.mode1 = mode1;
			this.sectorBytes = sectorBytes;
		}

		static Track parse(String fileName, String[] words) {
			// MODE1/2048 and MODE1/2352 name a data track; audio tracks carry nothing to load.
			int slash = words.length > 2 ? words[2].indexOf('/') : -1;
			String type = words.length > 2
				? (slash < 0 ? words[2] : words[2].substring(0, slash)).toUpperCase()
				: "";
			int size = slash < 0 ? 0 : toInt(words[2].substring(slash + 1));
			return new Track(fileName, "MODE1".equals(type), size);
		}

		void addIndex(String[] words) {
			if (words.length < 3 || !"01".equals(words[1]) || startFrame >= 0) {
				return;
			}
			String[] clock = words[2].split(":");
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
			return sectorBytes != 0 && startFrame >= 0;
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

	int sectorBytes() {
		return sectorBytes;
	}

	long trackStart() {
		return trackStart;
	}

	String getFileName() {
		return provider.getName();
	}

	void close() throws IOException {
		if (ownsProvider) {
			provider.close();
		}
	}
}

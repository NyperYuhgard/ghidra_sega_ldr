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

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

/**
 * The 512 bytes the BIOS reads from the first sector of a Sega CD disc. The names of the fields at
 * 0x50 and on follow what the mastering tools of the time put there and nothing more: the console
 * reads them, this module does not claim to know what every one of them decides.
 */
class CdHeader {

	static final int SIZE = 512;

	static final CategoryPath CATEGORY = new CategoryPath("/Sega/Sega CD");

	private final byte[] raw;

	CdHeader(BinaryReader reader, long offset) throws IOException {
		this.raw = reader.readByteArray(offset, SIZE);
	}

	/**
	 * A program area a disc declares, as the offset of its first byte counted in user data and the
	 * length the boot stage copies.
	 */
	record Program(long discAddress, long length) {

		boolean isPresent() {
			return discAddress > 0 && length > 0;
		}
	}

	/**
	 * The program of the processor of the drive, which the boot stage reads from where the header
	 * says and runs from the program RAM the drive is given.
	 */
	Program subProgram() {
		return new Program(unsignedInt(0x40), unsignedInt(0x44));
	}

	/**
	 * The second pair of the header, which every sheet of the hardware calls the area of the
	 * console's own processor. Nothing copies the console's program from where the pair says,
	 * though: it always comes from inside the header sector. The pair is reported and used for
	 * nothing else.
	 */
	Program mainProgram() {
		return new Program(unsignedInt(0x48), unsignedInt(0x4c));
	}

	private long unsignedInt(int offset) {
		return (raw[offset] & 0xffL) << 24 | (raw[offset + 1] & 0xffL) << 16
				| (raw[offset + 2] & 0xffL) << 8 | raw[offset + 3] & 0xffL;
	}

	/** The text of a field, cut at the first space or byte that is not printable. */
	String text(int offset, int length) {
		StringBuilder text = new StringBuilder(length);
		for (int i = 0; i < length; i++) {
			char c = (char) (raw[offset + i] & 0xff);
			if (c <= ' ' || c > '~') {
				break;
			}
			text.append(c);
		}
		return text.toString().trim();
	}

	String systemName() {
		return text(0x0, 16);
	}

	String deviceInfo() {
		return text(0x10, 16);
	}

	String versionInfo() {
		return text(0x20, 8);
	}

	/** The release date as the mastering sheet prints it, usually {@code YY/MM/DD}. */
	String releaseDate() {
		return text(0x30, 8);
	}

	/**
	 * The regions a disc asks for, read from the area field the way the console reads it: the
	 * letters it holds name the territories the game may start in.
	 */
	String regions() {
		String area = text(0x28, 8);
		StringBuilder regions = new StringBuilder();
		for (char c : area.toUpperCase().toCharArray()) {
			if ("JUE".indexOf(c) < 0) {
				continue;
			}
			regions.append(c == 'J' ? "Japan " : c == 'U' ? "USA " : "Europe ");
		}
		String listed = regions.toString().trim();
		return listed.isEmpty() ? area : listed;
	}

	ghidra.program.model.data.DataType toDataType() {
		Structure s = new StructureDataType("CdHeader", SIZE);

		s.add(new ArrayDataType(ByteDataType.dataType, 16, 1), 16, "SystemName",
			"SEGADISCSYSTEM for a disc that boots the console");
		s.add(new ArrayDataType(ByteDataType.dataType, 16, 1), 16, "DeviceInfo",
			"the device class Sega's sheet names, usually ROM/IGA-");
		s.add(new ArrayDataType(ByteDataType.dataType, 8, 1), 8, "VersionInfo",
			"version of the CD system the game was mastered for");
		s.add(new ArrayDataType(ByteDataType.dataType, 8, 1), 8, "AreaSupport",
			"letters of the territories the game may start in");
		s.add(new ArrayDataType(ByteDataType.dataType, 8, 1), 8, "ReleaseDate", null);
		s.add(new ArrayDataType(ByteDataType.dataType, 8, 1), 8, "Reserved",
			"kept for Sega's own sheet, no console reads it");

		s.add(DWordDataType.dataType, 4, "Program1DiscAddress",
			"offset in the user data area of the disc where the first declared program begins");
		s.add(DWordDataType.dataType, 4, "Program1Length",
			"byte count the BIOS copies from there into program RAM");
		s.add(DWordDataType.dataType, 4, "Program2DiscAddress",
			"offset of the second declared program");
		s.add(DWordDataType.dataType, 4, "Program2Length", null);

		s.add(DWordDataType.dataType, 4, "IoSupport",
			"peripherals the game expects, spelled the way the cartridge header's I/O byte does");
		s.add(DWordDataType.dataType, 4, "SubUnitSupport", null);
		s.add(new ArrayDataType(ByteDataType.dataType, 8, 1), 8, "Reserved2", null);

		s.add(new ArrayDataType(ByteDataType.dataType, 32, 1), 32, "BackupRamInfo",
			"the window and size of battery RAM the game expects to find");
		s.add(new ArrayDataType(ByteDataType.dataType, 64, 1), 64, "Notes",
			"free text of the mastering sheet");
		s.add(new ArrayDataType(ByteDataType.dataType, SIZE - 0xc0, 1), SIZE - 0xc0, "Unused", null);

		return s;
	}
}

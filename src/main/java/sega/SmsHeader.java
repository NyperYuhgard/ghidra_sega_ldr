package sega;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * The 16 byte Sega header of a Master System or Game Gear cartridge. Nothing in it is a string:
 * every field is a nibble or a little endian word, and several of them carry two facts in one byte.
 */
class SmsHeader implements StructConverter {

	/**
	 * The offsets a header can sit at, in the order the console's own start up code looks for it.
	 * A 48 KiB image keeps it at the end of the second page, so 0x7ff0 covers the 32 KiB and every
	 * banked image above it.
	 */
	static final long[] HEADER_OFFSETS = { 0x7ff0, 0x3ff0, 0x1ff0 };

	private static final String SIGNATURE = "TMR SEGA";

	/** Region nibble of the last header byte. */
	private static final int REGION_SMS_JAPAN = 0x3;
	private static final int REGION_SMS_EXPORT = 0x4;
	private static final int REGION_GAME_GEAR_FIRST = 0x5;
	private static final int REGION_GAME_GEAR_LAST = 0x7;

	/** How much of the image is added to the checksum at a time. */
	private static final int CHUNK = 0x10000;

	/**
	 * Total size of the ROM the checksum range nibble describes, indexed by that nibble. The
	 * console only ever checksums up to the second page and then resumes at 0x8000, so the nibble
	 * says how far that second run goes.
	 */
	private static final long[] RANGE_ROM_SIZE = {
		0x40000L, 0x80000L, 0x100000L, 0L, 0L, 0L, 0L, 0L, 0L, 0L,
		0x2000L, 0x4000L, 0x8000L, 0xc000L, 0x10000L, 0x20000L
	};

	private final byte[] raw;

	SmsHeader(BinaryReader reader, long offset) throws IOException {
		this.raw = reader.readByteArray(offset, 16);
	}

	private static boolean hasSignatureAt(BinaryReader reader, long offset) throws IOException {
		return reader.length() >= offset + 16
			&& SIGNATURE.equals(reader.readAsciiString(offset, SIGNATURE.length()));
	}

	/** Offset of the header inside the image, or -1 when the image carries none. */
	static long find(BinaryReader reader) throws IOException {
		for (long offset : HEADER_OFFSETS) {
			if (hasSignatureAt(reader, offset)) {
				return offset;
			}
		}
		return -1;
	}

	@Override
	public DataType toDataType() {
		Structure s = new StructureDataType(SegaDataTypes.SEGA, "SmsHeader", 0);

		s.add(STRING, 0x8, "Signature", null);
		s.add(WORD, 0x2, "Reserved", "reserved by Sega, never used; often the sequence number of the game on Game Gear");
		s.add(WORD, 0x2, "Checksum", "sum of every byte the range nibble selects, kept in 16 bits");
		s.add(WORD, 0x2, "ProductCode", "binary coded decimal, most significant digit first");
		s.add(BYTE, 0x1, "VersionAndProduct", "low nibble is the version, high nibble the fifth digit of the product code");
		s.add(BYTE, 0x1, "RegionAndRange", "high nibble is the region, low nibble the size the checksum runs over");

		return s;
	}

	int getChecksum() {
		return readWord(0xa);
	}

	/**
	 * The product code as Sega prints it: two BCD bytes followed by the high nibble of the next
	 * byte as the leading digit.
	 */
	String getProductCode() {
		StringBuilder digits = new StringBuilder();
		int lead = raw[0xe] >>> 4;
		if (lead >= 0xa) {
			digits.append('1').append((char) ('0' + lead - 0xa));
		}
		else {
			digits.append((char) ('0' + lead));
		}
		for (int i = 0xd; i >= 0xc; i--) {
			digits.append(Character.toUpperCase(Character.forDigit(raw[i] >>> 4, 16)));
			digits.append(Character.toUpperCase(Character.forDigit(raw[i] & 0xf, 16)));
		}
		return digits.toString();
	}

	int getVersion() {
		return raw[0xe] & 0xf;
	}

	int getRegionNibble() {
		return raw[0xf] >>> 4;
	}

	int getChecksumRangeNibble() {
		return raw[0xf] & 0xf;
	}

	boolean isGameGear() {
		int region = getRegionNibble();
		return region >= REGION_GAME_GEAR_FIRST && region <= REGION_GAME_GEAR_LAST;
	}

	String getRegionName() {
		return switch (getRegionNibble()) {
			case REGION_SMS_JAPAN -> "Master System (Japan)";
			case REGION_SMS_EXPORT -> "Master System (export)";
			case 0x5 -> "Game Gear (Japan)";
			case 0x6 -> "Game Gear (export)";
			case 0x7 -> "Game Gear (international)";
			default -> String.format("unknown region nibble %X", getRegionNibble());
		};
	}

	/**
	 * Size of the ROM the checksum range nibble describes, or -1 when the nibble is one the
	 * console's start up code does not accept.
	 */
	long getDeclaredRomSize() {
		long size = RANGE_ROM_SIZE[getChecksumRangeNibble()];
		return size == 0 ? -1 : size;
	}

	private int readWord(int at) {
		return (raw[at] & 0xff) | ((raw[at + 1] & 0xff) << 8);
	}

	/**
	 * The checksum the export Master System BIOS demands: every byte of the first two pages up to
	 * the header, then everything from 0x8000 to the size the range nibble gives, all added in a
	 * 16 bit accumulator.
	 */
	static int byteSum(BinaryReader reader, long headerOffset, long romSize, TaskMonitor monitor)
			throws IOException, CancelledException {

		long end = Math.min(Math.max(romSize, headerOffset), reader.length());
		monitor.initialize(end);
		monitor.setMessage("Calculating checksum");

		int sum = 0;
		sum = addRange(reader, sum, 0, headerOffset, monitor);
		if (end > 0x8000) {
			sum = addRange(reader, sum, 0x8000, end, monitor);
		}
		return sum & 0xffff;
	}

	private static int addRange(BinaryReader reader, int sum, long start, long end,
			TaskMonitor monitor) throws IOException, CancelledException {

		for (long at = start; at < end; at += CHUNK) {
			monitor.checkCancelled();
			monitor.setProgress(at);
			byte[] chunk = reader.readByteArray(at, (int) Math.min(CHUNK, end - at));
			for (byte b : chunk) {
				sum += b & 0xff;
			}
		}
		return sum & 0xffff;
	}

	/**
	 * Codemasters carts keep their own header right below the Sega one: a BCD timestamp followed by
	 * a checksum and its complement. Those two properties together are what separate the carts that
	 * page through writes at 0x0000, 0x4000 and 0x8000 from the ones that page through 0xfffc.
	 */
	static boolean hasCodemastersHeader(BinaryReader reader, long headerOffset) throws IOException {
		if (headerOffset < 0x10 || reader.length() < headerOffset + 16) {
			return false;
		}

		for (long at = headerOffset - 0xf; at <= headerOffset - 0xb; at++) {
			int b = reader.readByte(at) & 0xff;
			if ((b & 0xf0) > 0x90 || (b & 0x0f) > 0x09) {
				return false;
			}
		}

		int checksum = (reader.readByte(headerOffset - 0xa) & 0xff)
			| ((reader.readByte(headerOffset - 0x9) & 0xff) << 8);
		int complement = (reader.readByte(headerOffset - 0x8) & 0xff)
			| ((reader.readByte(headerOffset - 0x7) & 0xff) << 8);
		return complement == 0x10000 - checksum;
	}

	/**
	 * The Codemasters rule: the little endian 16-bit words of the whole image added into a 16 bit
	 * accumulator, with the Sega header skipped because the checksum has to survive being written
	 * into the file.
	 */
	static int codemastersWordSum(BinaryReader reader, long headerOffset, TaskMonitor monitor)
			throws IOException, CancelledException {

		long end = reader.length() & ~1L;
		monitor.initialize(end / 2);
		monitor.setMessage("Calculating checksum");

		int sum = 0;
		for (long at = 0; at < end; at += 2) {
			if (at >= headerOffset && at < headerOffset + 16) {
				continue;
			}
			if ((at & (CHUNK - 1)) == 0) {
				monitor.checkCancelled();
				monitor.setProgress(at / 2);
			}
			int word = (reader.readByte(at) & 0xff) | ((reader.readByte(at + 1) & 0xff) << 8);
			sum += word;
		}
		return sum & 0xffff;
	}
}

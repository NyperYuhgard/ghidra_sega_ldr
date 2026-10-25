package sega;

import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.WordDataType;

/**
 * The eighteen bytes of the video chip's window, spelled the way the loader names them: the two
 * halves of the data port, the two of the control port, the two mirrors the chip answers with its
 * status, and the sound byte the 68000 reaches at the odd address. Nothing here goes past those
 * names, because no register of this window is documented by anything this extension reads.
 */
final class VdpWindow {

	static final long BASE_ADDRESS = 0xC00000L;
	static final int SIZE = 2 * 9;

	private VdpWindow() {
	}

	/**
	 * The window as a structure. It stays in the catalogue rather than over the listing: the block
	 * holds no bytes of an image, and Ghidra refuses to define a data unit over memory that has
	 * none.
	 */
	static DataType toDataType() {
		Structure s = new StructureDataType(SegaDataTypes.SEGA, "VdpWindow", SIZE);

		s.add(WordDataType.dataType, 2, "VDP_DATA", null);
		s.add(WordDataType.dataType, 2, "VDP__DATA", null);
		s.add(WordDataType.dataType, 2, "VDP_CTRL", null);
		s.add(WordDataType.dataType, 2, "VDP__CTRL", null);
		s.add(WordDataType.dataType, 2, "VDP_CNTR", null);
		s.add(WordDataType.dataType, 2, "VDP__CNTR", null);
		s.add(WordDataType.dataType, 2, "VDP___CNTR", null);
		s.add(WordDataType.dataType, 2, "VDP____CNTR", null);
		s.add(ByteDataType.dataType, 1, "Reserved", null);
		s.add(ByteDataType.dataType, 1, "VDP_PSG", null);

		return s;
	}
}

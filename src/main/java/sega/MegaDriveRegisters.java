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

import ghidra.app.cmd.data.CreateArrayCmd;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;

/**
 * The peripheral registers of a Mega Drive as the 68000 wired to them sees them. A cartridge and a
 * Sega CD drive their processor through the same silicon, and the ASIC of the drive takes the port
 * region a cart gives to a floppy controller, so both loaders name this hardware from here.
 */
final class MegaDriveRegisters {

	private final Program program;
	private final FlatProgramAPI fpa;
	private final MessageLog log;
	private final String loaderName;

	private MegaDriveRegisters(Program program, FlatProgramAPI fpa, MessageLog log,
			String loaderName) {

		this.program = program;
		this.fpa = fpa;
		this.log = log;
		this.loaderName = loaderName;
	}

	/**
	 * @param mars true when a 32X hangs off the cartridge port, which claims the top of the timer
	 *            region for its bank register and its own signature
	 * @param cdAsic true when the drive's ASIC owns 0xA12000, the range a cartridge gives to the
	 *            floppy controller
	 */
	static void create(Program program, FlatProgramAPI fpa, MessageLog log, String loaderName,
			boolean mars, boolean cdAsic) {

		new MegaDriveRegisters(program, fpa, log, loaderName).build(mars, cdAsic);
	}

	private void build(boolean mars, boolean cdAsic) {
		block("Z80", 0xA00000L, 0x10000L, true, true, false, false);
		data(0xA04000L, "Z80_YM2612", DWordDataType.dataType);

		block("SYS1", 0xA10000L, 16 * 2, true, true, false, true);
		data(0xA10000L, "IO_PCBVER", WordDataType.dataType);
		data(0xA10002L, "IO_CT1_DATA", WordDataType.dataType);
		data(0xA10004L, "IO_CT2_DATA", WordDataType.dataType);
		data(0xA10006L, "IO_EXT_DATA", WordDataType.dataType);
		data(0xA10008L, "IO_CT1_CTRL", WordDataType.dataType);
		data(0xA1000AL, "IO_CT2_CTRL", WordDataType.dataType);
		data(0xA1000CL, "IO_EXT_CTRL", WordDataType.dataType);
		data(0xA1000EL, "IO_CT1_RX", WordDataType.dataType);
		data(0xA10010L, "IO_CT1_TX", WordDataType.dataType);
		data(0xA10012L, "IO_CT1_SMODE", WordDataType.dataType);
		data(0xA10014L, "IO_CT2_RX", WordDataType.dataType);
		data(0xA10016L, "IO_CT2_TX", WordDataType.dataType);
		data(0xA10018L, "IO_CT2_SMODE", WordDataType.dataType);
		data(0xA1001AL, "IO_EXT_RX", WordDataType.dataType);
		data(0xA1001CL, "IO_EXT_TX", WordDataType.dataType);
		data(0xA1001EL, "IO_EXT_SMODE", WordDataType.dataType);

		block("SYS2", 0xA11000L, 2, true, true, false, true);
		data(0xA11000L, "IO_RAMMODE", WordDataType.dataType);

		block("Z802", 0xA11100L, 2, true, true, false, true);
		data(0xA11100L, "IO_Z80BUS", WordDataType.dataType);

		block("Z803", 0xA11200L, 2, true, true, false, true);
		data(0xA11200L, "IO_Z80RES", WordDataType.dataType);

		if (!cdAsic) {
			block("FDC", 0xA12000L, 0x100, true, true, false, true);
			array(0xA12000L, "IO_FDC", 0x100, ByteDataType.dataType);
		}

		int timeSize = mars ? 0xEC : 0x100;
		block("TIME", 0xA13000L, timeSize, true, true, false, true);
		array(0xA13000L, "IO_TIME", timeSize, ByteDataType.dataType);

		block("TMSS", 0xA14000L, 4, true, true, false, true);
		data(0xA14000L, "IO_TMSS", DWordDataType.dataType);

		block("VDP", VdpWindow.BASE_ADDRESS, VdpWindow.SIZE, true, true, false, true);
		data(0xC00000L, "VDP_DATA", WordDataType.dataType);
		data(0xC00002L, "VDP__DATA", WordDataType.dataType);
		data(0xC00004L, "VDP_CTRL", WordDataType.dataType);
		data(0xC00006L, "VDP__CTRL", WordDataType.dataType);
		data(0xC00008L, "VDP_CNTR", WordDataType.dataType);
		data(0xC0000AL, "VDP__CNTR", WordDataType.dataType);
		data(0xC0000CL, "VDP___CNTR", WordDataType.dataType);
		data(0xC0000EL, "VDP____CNTR", WordDataType.dataType);
		data(0xC00011L, "VDP_PSG", ByteDataType.dataType);

		// Ghidra refuses to define a data unit over a block that carries no bytes, and a register
		// window never carries any of the image, so the layout waits in the catalogue.
		SegaDataTypes.register(program, VdpWindow.toDataType());
		log.appendMsg(String.format(
			"VdpWindow describes the %d bytes at 0x%X and is kept in /Sega: those addresses belong "
				+ "to registers, which hold nothing an image could give",
			VdpWindow.SIZE, VdpWindow.BASE_ADDRESS));
	}

	private void block(String name, long address, long size, boolean read, boolean write,
			boolean execute, boolean isVolatile) {

		MemoryBlock block = MemoryBlockUtils.createUninitializedBlock(program, false, name,
			toAddr(address), size, null, loaderName, read, write, execute, log);
		if (block != null) {
			block.setVolatile(isVolatile);
		}
	}

	private void data(long address, String name, DataType type) {
		try {
			if (type.equals(ByteDataType.dataType)) {
				fpa.createByte(toAddr(address));
			}
			else if (type.equals(WordDataType.dataType)) {
				fpa.createWord(toAddr(address));
			}
			else if (type.equals(DWordDataType.dataType)) {
				fpa.createDWord(toAddr(address));
			}
			label(address, name);
		}
		catch (Exception e) {
			log.appendException(e);
		}
	}

	private void array(long address, String name, int numElements, DataType type) {
		CreateArrayCmd arrayCmd = new CreateArrayCmd(toAddr(address), numElements, type,
			type.getLength());
		if (arrayCmd.applyTo(program)) {
			label(address, name);
		}
		else {
			log.appendMsg(name + ": " + arrayCmd.getStatusMsg());
		}
	}

	private void label(long address, String name) {
		try {
			program.getSymbolTable().createLabel(toAddr(address), name, SourceType.IMPORTED);
		}
		catch (InvalidInputException e) {
			log.appendException(e);
		}
	}

	private Address toAddr(long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}
}

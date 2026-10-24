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
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.*;

import ghidra.app.cmd.data.CreateArrayCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loaded;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Loader for Sega Mega Drive / Genesis ROMs. Builds the console's 68000 address space (or the
 * Sega 32X SH-2 view of it) so that absolute hardware addresses found in the code resolve to
 * labeled registers rather than to unknown memory.
 */
public class SegaLoader extends AbstractProgramLoader {

	public static final String LOADER_NAME = "Sega Mega Drive / Genesis Loader";

	private static final String M68K_LANGUAGE_ID = "68000:BE:32:MC68020";
	private static final String SH2_LANGUAGE_ID = "SuperH:BE:32:SH-2";

	private static final long ROM_REGION_SIZE = 0x400000L;
	private static final long MAX_BACKUP_RAM_SIZE = 0x20000L;
	private static final long MAX_WORK_RAM_SIZE = 0x100000L;
	private static final String REGION_CODES = "JUEBKRFX?";
	private static final long MARS_CHECK_MODE_OFFSET = 0x3c0;
	private static final String MARS_CHECK_MODE = "MARS CHECK MODE";

	@Override
	public String getName() {
		return LOADER_NAME;
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 0;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		if (provider.length() >= MARS_CHECK_MODE_OFFSET + MARS_CHECK_MODE.length()) {
			BinaryReader reader = new BinaryReader(provider, false);
			if (reader.readAsciiString(0x100, 4).equals("SEGA")) {
				loadSpecs.add(new LoadSpec(this, 0,
					new LanguageCompilerSpecPair(M68K_LANGUAGE_ID, "default"), true));

				if (is32XCartridge(reader)) {
					loadSpecs.add(new LoadSpec(this, 0,
						new LanguageCompilerSpecPair(SH2_LANGUAGE_ID, "default"), false));
				}
			}
		}

		return loadSpecs;
	}

	private static boolean is32XCartridge(BinaryReader reader) throws IOException {
		return reader.readAsciiString(MARS_CHECK_MODE_OFFSET, MARS_CHECK_MODE.length())
				.equals(MARS_CHECK_MODE);
	}

	@Override
	protected List<Loaded<Program>> loadProgram(ImporterSettings settings)
			throws IOException, CancelledException {
		Program program = createProgram(settings);
		Loaded<Program> loaded = new Loaded<>(program, settings);

		boolean success = false;
		try {
			loadInto(program, settings);
			success = true;
			return List.of(loaded);
		}
		finally {
			if (!success) {
				loaded.close();
			}
		}
	}

	@Override
	protected void loadProgramInto(Program program, ImporterSettings settings)
			throws IOException, CancelledException {
		new MemoryMap(program, settings).build();
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> options = super.getDefaultOptions(provider, loadSpec, domainObject,
			loadIntoProgram, mirrorFsLayout);

		boolean marsRom = false;
		try {
			marsRom = is32XCartridge(new BinaryReader(provider, false));
		}
		catch (IOException e) {
			// Too short to carry the MARS signature; the selected language still decides.
		}

		options.addAll(SegaLoadOptions.options(marsRom || usesSh2Language(loadSpec), false));
		return options;
	}

	static boolean usesSh2Language(LoadSpec loadSpec) {
		String languageID =
			loadSpec.getLanguageCompilerSpec().getLanguageID().getIdAsString();
		return languageID.contains("SuperH");
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {

		String path = SegaLoadOptions.from(options, false, false).sramFile();
		if (path == null) {
			return null;
		}

		try {
			if (!Files.isRegularFile(Path.of(path))) {
				return SegaLoadOptions.NAME_SRAM_FILE + ": no such file: " + path;
			}
		}
		catch (InvalidPathException e) {
			return SegaLoadOptions.NAME_SRAM_FILE + ": " + path;
		}

		return null;
	}

	/**
	 * The 68000 (or SH-2) address space of one ROM image. Exists per load so that the loader
	 * itself stays stateless.
	 */
	private static class MemoryMap {

		private final Program program;
		private final ByteProvider provider;
		private final MessageLog log;
		private final TaskMonitor monitor;
		private final SegaLoadOptions options;
		private final boolean hasSH2MemoryMap;
		private final boolean has32XSegments;

		private final FlatProgramAPI fpa;
		private final Memory memory;

		private final FileBytes romBytes;
		private final long romLength;

		MemoryMap(Program program, ImporterSettings settings)
				throws IOException, CancelledException {
			this.program = program;
			this.provider = settings.provider();
			this.log = settings.log();
			this.monitor = settings.monitor();
			this.romLength = this.provider.length();
			this.fpa = new FlatProgramAPI(program, monitor);
			this.memory = program.getMemory();
			this.romBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);

			LoadSpec loadSpec = settings.loadSpec();
			this.hasSH2MemoryMap = usesSh2Language(loadSpec);
			this.options = SegaLoadOptions.from(settings.options(), hasSH2MemoryMap, false);
			this.has32XSegments = options.create32XSegments();
		}

		void build() throws IOException, CancelledException {
			monitor.setMessage(String.format("%s : Start loading", LOADER_NAME));

			BinaryReader reader = new BinaryReader(provider, false);

			VectorsTable vectors = null;
			GameHeader header = null;
			MarsUserHeader marsUserHeader = null;
			if (!hasSH2MemoryMap) {
				vectors = new VectorsTable(fpa, reader);
				header = new GameHeader(reader);
			}
			if (has32XSegments) {
				marsUserHeader = new MarsUserHeader(reader);
			}

			createSegments(header, marsUserHeader);

			if (!hasSH2MemoryMap) {
				markVectorsTable(vectors);
				markHeader(header);
				createBackupRam(header);
				createWorkRam(header);
				if (options.verify()) {
					verifyHeader(reader, header);
				}
			}
			if (has32XSegments) {
				markMarsUserHeader(marsUserHeader);
			}

			monitor.setMessage(String.format("%s : Loading done", LOADER_NAME));
		}

		private void createSegments(GameHeader header, MarsUserHeader marsUserHeader)
				throws IOException {

			if (!hasSH2MemoryMap) {
				romBlock("ROM", 0x000000L, 0L, declaredRomSize(header), true, false, true);
			}

			if (options.createSegaCDSegments()) {
				if (romLength > ROM_REGION_SIZE) {
					romBlock("EPA", 0x400000L, ROM_REGION_SIZE, ROM_REGION_SIZE, true, true, false);
				}
				else {
					memBlock("EPA", 0x400000L, ROM_REGION_SIZE, true, true, false, false);
				}
			}

			if (has32XSegments) {
				memBlock("32X_PRIV", 0x800000L, 0x40000L, true, true, false, false);
				memBlock("32X_DRAM", 0x840000L, 0x20000L, true, true, false, false);
				memBlock("32X_OWIMG", 0x860000L, 0x20000L, true, true, false, false);

				romBlock("32X_ROM_FIXED", 0x880000L, 0L, 0x80000L, true, true, true);
				long bankSize = 0x100000L;
				for (int i = 0; i < 4; i++) {
					long fileOffset = Math.min(romLength, bankSize * i);
					romBlock("32X_ROM_BANK" + i, 0x900000L + bankSize * i, fileOffset, bankSize,
						true, true, true, true);
					if (romLength < bankSize * (i + 1)) {
						break;
					}
				}

				memBlock("32X_ID", 0xA130ECL, 0x4L, true, true, false, false);
				createNamedData(0xA130ECL, "IO_32X_ID", DWordDataType.dataType);

				memBlock("32X_BANK_SET_REG", 0xA130F1L, 0xFL, true, true, false, false);
				createNamedArray(0xA130F1L, "IO_32X_BANK_SET_REG", 0xF, WordDataType.dataType);

				memBlock("32X_SYS_REG", 0xA15100L, 0x80L, true, true, false, false);
				createNamedData(0xA15100L, "IO_32X_VDP_CTRL", ByteDataType.dataType);
				createNamedData(0xA15101L, "IO_32X_ADAPTER_CTRL", ByteDataType.dataType);
				createNamedData(0xA15102L, "IO_32X_SH2_INT_CTRL", WordDataType.dataType);
				createNamedData(0xA15104L, "IO_32X_BANK_CTRL", WordDataType.dataType);
				createNamedData(0xA15106L, "IO_32X_DREQ_CTRL", WordDataType.dataType);
				createNamedData(0xA15108L, "IO_32X_68K_SH2_DREQ_SRC", DWordDataType.dataType);
				createNamedData(0xA1510cL, "IO_32X_68K_SH2_DREQ_DEST", DWordDataType.dataType);
				createNamedData(0xA15110L, "IO_32X_68K_SH2_DREQ_LEN", WordDataType.dataType);
				createNamedData(0xA15112L, "IO_32X_68K_SH2_DREQ_FIFO", WordDataType.dataType);
				createNamedData(0xA1511bL, "IO_32X_SEGA_TV_REG", ByteDataType.dataType);
				createNamedArray(0xA15120L, "IO_32X_COMM", 0x10, ByteDataType.dataType);
				createNamedData(0xA15130L, "IO_32X_PWM_CTRL", WordDataType.dataType);
				createNamedData(0xA15132L, "IO_32X_CYCLE_REG", WordDataType.dataType);
				createNamedData(0xA15134L, "IO_32X_L_CH_PULSE_REG", WordDataType.dataType);
				createNamedData(0xA15136L, "IO_32X_R_CH_PULSE_REG", WordDataType.dataType);
				createNamedData(0xA15138L, "IO_32X_MONO_PULSE_REG", WordDataType.dataType);

				memBlock("32X_VDP_REG", 0xA15180L, 0x80L, true, true, false, false);
				createNamedArray(0xA15180L, "IO_32X_VDP_REG", 0x80, ByteDataType.dataType);

				memBlock("32X_PAL", 0xA15200L, 0x200L, true, true, false, false);
				createNamedArray(0xA15200L, "IO_32X_PAL", 0x100, WordDataType.dataType);

				if (hasSH2MemoryMap) {
					createSh2Segments(marsUserHeader);
				}
				else {
					// A 32X keeps a second jump table right after its MARS user header.
					disassembleRange(0x200L, 0x3c0L);
				}
			}

			if (options.createHardwareRegisters()) {
				createHardwareRegisters();
			}
		}

		private void createSh2Segments(MarsUserHeader marsUserHeader) throws IOException {

			// SH-2 cache
			romBlock("SH2_BOOT_ROM", 0x00000000L, 0L, 0x4000L, true, false, true);

			memBlock("SH2_SYS_REG", 0x00004000L, 0x100L, true, true, false, false);
			createNamedData(0x00004000L, "IO_SH2_ADAPTER_CTRL", ByteDataType.dataType);
			createNamedData(0x00004001L, "IO_SH2_INT_CTRL", ByteDataType.dataType);
			createNamedData(0x00004002L, "IO_SH2_STANDBY", WordDataType.dataType);
			createNamedData(0x00004005L, "IO_SH2_H_COUNT_REG", ByteDataType.dataType);
			createNamedData(0x00004006L, "IO_SH2_DREQ_CTRL", ByteDataType.dataType);
			createNamedData(0x00004008L, "IO_SH2_DREQ_SRC", DWordDataType.dataType);
			createNamedData(0x0000400cL, "IO_SH2_DREQ_DEST", DWordDataType.dataType);
			createNamedData(0x00004010L, "IO_SH2_DREQ_LEN", WordDataType.dataType);
			createNamedData(0x00004012L, "IO_SH2_DREQ_FIFO", WordDataType.dataType);
			createNamedData(0x00004014L, "IO_SH2_VRES_INT_CLEAR", WordDataType.dataType);
			createNamedData(0x00004016L, "IO_SH2_V_INT_CLEAR", WordDataType.dataType);
			createNamedData(0x00004018L, "IO_SH2_H_INT_CLEAR", WordDataType.dataType);
			createNamedData(0x0000401aL, "IO_SH2_CMD_INT_CLEAR", WordDataType.dataType);
			createNamedData(0x0000401cL, "IO_SH2_PWM_INT_CLEAR", WordDataType.dataType);
			createNamedData(0x0000401eL, "IO_SH2_UNUSED", WordDataType.dataType);
			createNamedArray(0x00004020L, "IO_SH2_COMM", 0x10, ByteDataType.dataType);
			createNamedData(0x00004030L, "IO_32X_TIMER_CTRL", ByteDataType.dataType);
			createNamedData(0x00004031L, "IO_32X_PWM_CTRL", ByteDataType.dataType);
			createNamedData(0x00004032L, "IO_32X_CYCLE_REG", WordDataType.dataType);
			createNamedData(0x00004034L, "IO_32X_L_CH_PULSE_REG", WordDataType.dataType);
			createNamedData(0x00004036L, "IO_32X_R_CH_PULSE_REG", WordDataType.dataType);
			createNamedData(0x00004038L, "IO_32X_MONO_PULSE_REG", WordDataType.dataType);

			memBlock("SH2_VDP_REG", 0x00004100L, 0x100L, true, true, false, false);
			memBlock("SH2_PAL", 0x00004200L, 0x200L, true, true, false, false);
			romBlock("SH2_ROM", 0x02000000L, 0L, 0x400000L, true, false, true);
			memBlock("SH2_DRAM", 0x04000000L, 0x20000L, true, true, false, false);
			memBlock("SH2_OWIMG", 0x04020000L, 0x20000L, true, true, false, false);
			romBlock("SH2_SDRAM", 0x06000000L, marsUserHeader.getSourceAddress(), 0x40000L, true,
				true, true);

			// SH-2 cache-through aliases
			mirrorBlock("SH2_CT_BOOT_ROM", 0x00000000L, 0x20000000L, 0x4000L);
			mirrorBlock("SH2_CT_SYS_REG", 0x00004000L, 0x20004000L, 0x100L);
			mirrorBlock("SH2_CT_VDP_REG", 0x00004100L, 0x20004100L, 0x100L);
			mirrorBlock("SH2_CT_PAL", 0x00004200L, 0x20004200L, 0x200L);
			romBlock("SH2_CT_ROM", 0x22000000L, 0L, 0x400000L, true, false, true);
			mirrorBlock("SH2_CT_DRAM", 0x04000000L, 0x24000000L, 0x20000L);
			mirrorBlock("SH2_CT_OWIMG", 0x04020000L, 0x24020000L, 0x20000L);
			mirrorBlock("SH2_CT_SDRAM", 0x06000000L, 0x26000000L, 0x40000L);

			createFunction(marsUserHeader.getSh2MasterStartAddress(), "SHM_entry");
			createFunction(marsUserHeader.getSh2SlaveStartAddress(), "SHS_entry");
		}

		private void createHardwareRegisters() {

			memBlock("Z80", 0xA00000L, 0x10000L, true, true, false, false);
			createNamedData(0xA04000L, "Z80_YM2612", DWordDataType.dataType);

			memBlock("SYS1", 0xA10000L, 16 * 2, true, true, false, true);
			createNamedData(0xA10000L, "IO_PCBVER", WordDataType.dataType);
			createNamedData(0xA10002L, "IO_CT1_DATA", WordDataType.dataType);
			createNamedData(0xA10004L, "IO_CT2_DATA", WordDataType.dataType);
			createNamedData(0xA10006L, "IO_EXT_DATA", WordDataType.dataType);
			createNamedData(0xA10008L, "IO_CT1_CTRL", WordDataType.dataType);
			createNamedData(0xA1000AL, "IO_CT2_CTRL", WordDataType.dataType);
			createNamedData(0xA1000CL, "IO_EXT_CTRL", WordDataType.dataType);
			createNamedData(0xA1000EL, "IO_CT1_RX", WordDataType.dataType);
			createNamedData(0xA10010L, "IO_CT1_TX", WordDataType.dataType);
			createNamedData(0xA10012L, "IO_CT1_SMODE", WordDataType.dataType);
			createNamedData(0xA10014L, "IO_CT2_RX", WordDataType.dataType);
			createNamedData(0xA10016L, "IO_CT2_TX", WordDataType.dataType);
			createNamedData(0xA10018L, "IO_CT2_SMODE", WordDataType.dataType);
			createNamedData(0xA1001AL, "IO_EXT_RX", WordDataType.dataType);
			createNamedData(0xA1001CL, "IO_EXT_TX", WordDataType.dataType);
			createNamedData(0xA1001EL, "IO_EXT_SMODE", WordDataType.dataType);

			memBlock("SYS2", 0xA11000L, 2, true, true, false, true);
			createNamedData(0xA11000L, "IO_RAMMODE", WordDataType.dataType);

			memBlock("Z802", 0xA11100L, 2, true, true, false, true);
			createNamedData(0xA11100L, "IO_Z80BUS", WordDataType.dataType);

			memBlock("Z803", 0xA11200L, 2, true, true, false, true);
			createNamedData(0xA11200L, "IO_Z80RES", WordDataType.dataType);

			memBlock("FDC", 0xA12000L, 0x100, true, true, false, true);
			createNamedArray(0xA12000L, "IO_FDC", 0x100, ByteDataType.dataType);

			// The last bytes of the timer region belong to the 32X bank register and 32X ID
			int timeSegmentSize = has32XSegments ? 0xEC : 0x100;
			memBlock("TIME", 0xA13000L, timeSegmentSize, true, true, false, true);
			createNamedArray(0xA13000L, "IO_TIME", timeSegmentSize, ByteDataType.dataType);

			memBlock("TMSS", 0xA14000L, 4, true, true, false, true);
			createNamedData(0xA14000L, "IO_TMSS", DWordDataType.dataType);

			memBlock("VDP", 0xC00000L, 2 * 9, true, true, false, true);
			createNamedData(0xC00000L, "VDP_DATA", WordDataType.dataType);
			createNamedData(0xC00002L, "VDP__DATA", WordDataType.dataType);
			createNamedData(0xC00004L, "VDP_CTRL", WordDataType.dataType);
			createNamedData(0xC00006L, "VDP__CTRL", WordDataType.dataType);
			createNamedData(0xC00008L, "VDP_CNTR", WordDataType.dataType);
			createNamedData(0xC0000AL, "VDP__CNTR", WordDataType.dataType);
			createNamedData(0xC0000CL, "VDP___CNTR", WordDataType.dataType);
			createNamedData(0xC0000EL, "VDP____CNTR", WordDataType.dataType);
			createNamedData(0xC00011L, "VDP_PSG", ByteDataType.dataType);

			memBlock("RAM", 0xFF0000L, 0x10000L, true, true, true, false);
			mirrorBlock("RAM", 0xFF0000L, 0xFFFF0000L, 0x10000L);
		}

		/**
		 * Size of the cartridge ROM as the hardware maps it: never smaller than the file, never
		 * larger than the region, and a header that promises more than the next power of two of the
		 * file is not believed.
		 */
		private long declaredRomSize(GameHeader header) {
			long fileSize = Math.min(romLength, ROM_REGION_SIZE);
			if (header == null || !header.isPresent() || header.getRomStart() != 0) {
				return fileSize;
			}

			long declared = header.getRomEnd() + 1;
			if (declared <= 0 || declared > ROM_REGION_SIZE) {
				return fileSize;
			}

			return Math.max(fileSize, Math.min(declared, nextPowerOfTwo(romLength)));
		}

		private static long nextPowerOfTwo(long value) {
			long power = 1;
			while (power < value) {
				power <<= 1;
			}
			return power;
		}

		/**
		 * Backup RAM, from the SRAM code and address range of the header. Carts usually place it
		 * over the upper part of the ROM window, where it only appears when the banked ROM is not;
		 * there the block is created only when the user points at a save file, otherwise the window
		 * keeps showing the program.
		 */
		private void createBackupRam(GameHeader header) throws IOException {
			if (!header.hasSRAM()) {
				return;
			}

			long start = header.getBackupRamStart();
			long size = header.getBackupRamEnd() - start + 1;
			if (size <= 0 || size > MAX_BACKUP_RAM_SIZE) {
				log.appendMsg(String.format(
					"header declares 0x%X byte(s) of backup RAM at 0x%X, no cartridge holds that much",
					size, start));
				return;
			}

			MemoryBlock covered = blockIntersecting(start, size);
			if (covered != null && options.sramFile() == null) {
				log.appendMsg(String.format(
					"backup RAM 0x%X-0x%X shares its window with %s; label only", start,
					start + size - 1, covered.getName()));
				label(start, "BACKUP_RAM");
				return;
			}

			MemoryBlock block;
			String mode = header.getBackupRamMode();
			String comment = "both".equals(mode) ? "declared by the ROM header"
				: String.format("%s bytes of the window declared by the ROM header", mode);
			if (options.sramFile() != null) {
				block = loadBackupRam(start, size, covered != null, comment);
			}
			else {
				block = MemoryBlockUtils.createUninitializedBlock(program, covered != null,
					"BACKUP_RAM", toAddr(start), size, comment, LOADER_NAME, true, true, false, log);
			}
			if (block == null) {
				return;
			}
			block.setVolatile(true);
		}

		private MemoryBlock loadBackupRam(long start, long declaredSize, boolean overlay,
				String comment) throws IOException {

			Path path = Path.of(options.sramFile());
			byte[] content = Files.readAllBytes(path);

			MemoryBlock block;
			try {
				// Zero filled to the size the header declares; the save only covers part of it
				// when the cart held more than the emulator dumped.
				block = program.getMemory().createInitializedBlock("BACKUP_RAM", toAddr(start),
					declaredSize, (byte) 0, monitor, overlay);
			}
			catch (LockException | MemoryConflictException | AddressOverflowException
					| IllegalArgumentException | CancelledException e) {
				log.appendException(e);
				return null;
			}

			block.setRead(true);
			block.setWrite(true);
			block.setExecute(false);
			block.setComment(comment);

			try {
				program.getMemory().setBytes(block.getStart(), content, 0,
					(int) Math.min(content.length, declaredSize));
			}
			catch (MemoryAccessException e) {
				log.appendException(e);
			}

			if (content.length != declaredSize) {
				log.appendMsg(String.format("%s holds 0x%X byte(s), backup RAM was declared as 0x%X",
					path, content.length, declaredSize));
			}
			return block;
		}

		/**
		 * Work RAM, for the carts that declare something other than the standard 64 KiB at
		 * 0xFF0000. The address the header gives is the one the game's own code uses.
		 */
		private void createWorkRam(GameHeader header) {
			if (!header.isPresent()) {
				return;
			}

			long start = header.getRamStart() & 0xFFFFFFL;
			long size = header.getRamEnd() - start + 1;
			if (size <= 0 || size > MAX_WORK_RAM_SIZE) {
				if (size > MAX_WORK_RAM_SIZE) {
					log.appendMsg(String.format(
						"header declares 0x%X byte(s) of work RAM at 0x%X, no cartridge holds that much",
						size, start));
				}
				return;
			}

			MemoryBlock covered = blockIntersecting(start, size);
			if (covered == null) {
				// Code never runs from work RAM on this hardware, but patched and homebrew images
				// sometimes load a routine there; the block stays out of the execute set so the
				// analyzer does not turn uninitialized RAM into strings of instructions.
				memBlock("WORK_RAM", start, size, true, true, false, true);
			}
			else if (start != 0xFF0000L || size != 0x10000L) {
				log.appendMsg(String.format(
					"header declares work RAM 0x%X-0x%X, %s already covers it", start,
					start + size - 1, covered.getName()));
			}
		}

		private MemoryBlock blockIntersecting(long start, long size) {
			Address first = toAddr(start);
			Address last = toAddr(start + size - 1);
			for (MemoryBlock block : memory.getBlocks()) {
				if (block.getStart().compareTo(last) <= 0
						&& block.getEnd().compareTo(first) >= 0) {
					return block;
				}
			}
			return null;
		}

		/** Block backed by the ROM image, clipped to what the file actually contains. */
		private void romBlock(String name, long address, long fileOffset, long size, boolean read,
				boolean write, boolean execute) {
			romBlock(name, address, fileOffset, size, read, write, execute, false);
		}

		private void romBlock(String name, long address, long fileOffset, long size, boolean read,
				boolean write, boolean execute, boolean overlay) {

			long available = fileOffset < romLength ? romLength - fileOffset : 0;
			long initialized = Math.min(size, available);

			try {
				if (initialized > 0) {
					MemoryBlockUtils.createInitializedBlock(program, overlay, name, toAddr(address),
						romBytes, fileOffset, initialized, null, LOADER_NAME, read, write, execute,
						log);
				}
				if (initialized < size) {
					if (initialized > 0) {
						log.appendMsg(String.format(
							"%s: file ends at offset 0x%X, %d trailing byte(s) of the block have no data",
							name, romLength, size - initialized));
						name = name + "_NO_DATA";
					}
					MemoryBlockUtils.createUninitializedBlock(program, overlay, name,
						toAddr(address + initialized), size - initialized, null, LOADER_NAME, read,
						write, execute, log);
				}
			}
			catch (AddressOverflowException e) {
				log.appendException(e);
			}
		}

		/** Console memory (work RAM, registers) that carries no file content. */
		private void memBlock(String name, long address, long size, boolean read, boolean write,
				boolean execute, boolean isVolatile) {
			MemoryBlock block = MemoryBlockUtils.createUninitializedBlock(program, false, name,
				toAddr(address), size, null, LOADER_NAME, read, write, execute, log);
			if (block != null) {
				block.setVolatile(isVolatile);
			}
		}

		/** Alias of an existing block at another address, sharing its bytes. */
		private void mirrorBlock(String name, long physicalAddress, long mappedAddress, long size) {
			Address base = toAddr(physicalAddress);
			try {
				MemoryBlock block = memory.createByteMappedBlock(name, toAddr(mappedAddress), base,
					size, false);
				MemoryBlock physical = memory.getBlock(base);
				block.setRead(physical.isRead());
				block.setWrite(physical.isWrite());
				block.setExecute(physical.isExecute());
				block.setVolatile(physical.isVolatile());
			}
			catch (LockException | MemoryConflictException | AddressOverflowException
					| IllegalArgumentException e) {
				log.appendException(e);
			}
		}

		/** Disassembles a range that is known to hold code but has no entry point. */
		private void disassembleRange(long start, long end) {
			AddressSet set = new AddressSet(toAddr(start), toAddr(end));
			Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
			while (!set.isEmpty()) {
				AddressSetView disassembled = dis.disassemble(set.getMinAddress(), set, true);
				if (disassembled.isEmpty()) {
					try {
						program.getBookmarkManager().removeBookmarks(set, BookmarkType.ERROR,
							Disassembler.ERROR_BOOKMARK_CATEGORY, monitor);
					}
					catch (CancelledException e) {
						log.appendException(e);
					}
					return;
				}
				AutoAnalysisManager.getAnalysisManager(program).codeDefined(disassembled);
				set.delete(disassembled);
			}
		}

		private void createFunction(long offset, String name) {
			Address address = toAddr(offset);
			fpa.createFunction(address, name);
			Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
			AddressSetView disassembled = dis.disassemble(address, null, false);
			AutoAnalysisManager.getAnalysisManager(program).codeDefined(disassembled);
		}

		private void markVectorsTable(VectorsTable vectors) {
			try {
				DataUtilities.createData(program, toAddr(0), vectors.toDataType(), -1, false,
					ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			}
			catch (CodeUnitInsertionException e) {
				log.appendException(e);
				return;
			}

			VectorFunc[] table = vectors.getVectors();
			for (int i = 0; i < table.length; i++) {
				VectorFunc vector = table[i];
				Address target = vector.getAddress();

				MemoryBlock block = memory.getBlock(target);
				if (block == null || !block.isExecute() || !block.isInitialized()
						|| block.isVolatile()) {
					// Reserved and unused vectors of shipped ROMs point into RAM or at nothing.
					if (target.getOffset() != 0) {
						program.getListing().setComment(toAddr(i * 4L), CommentType.EOL,
							String.format("%s does not reach runnable code (0x%X)",
								vector.getName(), target.getOffset()));
					}
					continue;
				}

				fpa.createFunction(target, vector.getName());
			}
		}

		private void markHeader(GameHeader header) {
			try {
				DataUtilities.createData(program, toAddr(GameHeader.HEADER_ADDRESS),
					header.toDataType(), -1, false,
					ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			}
			catch (CodeUnitInsertionException e) {
				log.appendException(e);
				return;
			}

			label(GameHeader.HEADER_ADDRESS, "GAME_HEADER");

			String description = String.format("%s\n%s  version %s  regions %s  controls %s\nROM 0x%06X-0x%06X  RAM 0x%06X-0x%06X  SRAM %s",
				GameHeader.ascii(header.getDomesticName()),
				GameHeader.ascii(header.getReleaseDate()),
				GameHeader.ascii(header.getVersion()),
				header.getRegionCodes(),
				GameHeader.ascii(header.getIoSupport()),
				header.getRomStart(), header.getRomEnd(),
				header.getRamStart(), header.getRamEnd(),
				header.hasSRAM()
						? String.format("0x%06X-0x%06X", header.getBackupRamStart(),
							header.getBackupRamEnd())
						: "none");

			program.getListing().setComment(toAddr(GameHeader.HEADER_ADDRESS),
				CommentType.PLATE, description);

			MemoryBlock rom = memory.getBlock("ROM");
			if (rom != null) {
				rom.setComment(GameHeader.ascii(header.getDomesticName()) + " ("
					+ GameHeader.ascii(header.getVersion()) + ", " + header.getRegionCodes() + ")");
			}
		}

		private void verifyHeader(BinaryReader reader, GameHeader header)
				throws IOException, CancelledException {

			if (!header.isPresent()) {
				reportProblem(GameHeader.HEADER_ADDRESS, "no \"SEGA\" signature at 0x100");
			}
			if (header.getRomStart() != 0) {
				reportProblem(0x1a0,
					String.format("ROM is declared to start at 0x%X", header.getRomStart()));
			}

			long romSize = declaredRomSize(header);
			if (romSize != romLength) {
				reportProblem(0x1a4, String.format(
					"header declares a ROM of 0x%X byte(s), the file is 0x%X byte(s)", romSize,
					romLength));
			}

			String regions = header.getRegionCodes();
			if (regions.isEmpty()) {
				reportProblem(0x1f0, "no supported region declared");
			}
			for (int i = 0; i < regions.length(); i++) {
				char code = regions.charAt(i);
				if (REGION_CODES.indexOf(code) < 0) {
					reportProblem(0x1f0, String.format("unknown region code '%c'", code));
				}
			}

			int declared = header.getChecksum() & 0xFFFF;
			int sum = Checksum.segaSum(reader, romSize, monitor);
			int xor = Checksum.sgdkXor(reader, romLength, monitor);
			String form = declared == sum ? Checksum.SEGA_SUM
				: declared == xor ? Checksum.SGDK_XOR : null;
			if (form == null) {
				program.getListing().setComment(toAddr(Checksum.FIELD_ADDRESS),
					CommentType.PRE, String.format(
						"header says 0x%04X, the ROM adds up to 0x%04X and XORs to 0x%04X", declared,
						sum, xor));
				reportProblem(Checksum.FIELD_ADDRESS, String.format(
					"checksum 0x%04X is neither the %s (0x%04X) nor the %s (0x%04X); a patched ROM usually keeps the value of the image it was cut from",
					declared, Checksum.SEGA_SUM, sum, Checksum.SGDK_XOR, xor));
			}
			else {
				log.appendMsg(String.format("checksum 0x%04X is correct (%s)", declared, form));
			}
		}

		private void reportProblem(long address, String message) {
			log.appendMsg(message);
			program.getBookmarkManager().setBookmark(toAddr(address), BookmarkType.WARNING,
				"Sega header", message);
		}

		private void markMarsUserHeader(MarsUserHeader marsUserHeader) {
			try {
				DataUtilities.createData(program, toAddr(0x3c0 + (hasSH2MemoryMap ? 0x880000L : 0)),
					marsUserHeader.toDataType(), -1, false,
					ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			}
			catch (CodeUnitInsertionException e) {
				log.appendException(e);
			}
		}

		private void createNamedArray(long address, String name, int numElements, DataType type) {
			CreateArrayCmd arrayCmd = new CreateArrayCmd(toAddr(address), numElements, type,
				type.getLength());
			if (arrayCmd.applyTo(program)) {
				label(address, name);
			}
			else {
				log.appendMsg(name + ": " + arrayCmd.getStatusMsg());
			}
		}

		private void createNamedData(long address, String name, DataType type) {
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

		private void label(long address, String name) {
			try {
				program.getSymbolTable().createLabel(toAddr(address), name, SourceType.IMPORTED);
			}
			catch (InvalidInputException e) {
				log.appendException(e);
			}
		}

		private Address toAddr(long offset) {
			return fpa.toAddr(offset);
		}
	}
}

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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.List;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loaded;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * What the two 68000 processors of a Sega CD disc have in common: recognizing the disc, reaching
 * the programs its header declares and naming the ASIC both of them are wired to. The address space
 * each processor is given is left to the loader of that processor, because the ASIC shows the same
 * memories to the two of them at different addresses.
 */
abstract class SegaCdLoaderBase extends AbstractProgramLoader {

	static final String M68K_LANGUAGE_ID = "68000:BE:32:MC68020";

	static final String NAME_BIOS_FILE = "CD BIOS image the console runs before the disc (.bin)";
	static final String NAME_BRAM_FILE = "Backup RAM contents file (.brm / .bkr)";
	static final String ARG_BIOS_FILE = Loader.COMMAND_LINE_ARG_PREFIX + "-cd-bios";
	static final String ARG_BRAM_FILE = Loader.COMMAND_LINE_ARG_PREFIX + "-cd-bram";

	/**
	 * Program RAM of the ASIC, the window the cartridge side of it is shown through, and the place
	 * the boot stage leaves for the program of the drive's own processor.
	 */
	private static final long PROG_RAM_SIZE = 0x80000L;
	private static final long PROG_RAM_PROGRAM_OFFSET = 0x6000L;
	private static final long PROG_WINDOW_FOR_MAIN = 0x20000L;
	private static final long PROG_WINDOW_SIZE_FOR_MAIN = 0x20000L;

	/**
	 * The work RAM of the console, its address for the processor of the cartridge side, and the
	 * program that boots with the disc: it starts inside the header sector of the disc and is no
	 * longer than the area the hardware keeps for it at the bottom of that work RAM.
	 */
	private static final long WORK_RAM_ADDRESS = 0xFF0000L;
	private static final long WORK_RAM_SIZE = 0x10000L;
	private static final long BOOT_PROGRAM_DISC_OFFSET = 0x200L;
	private static final long BOOT_PROGRAM_SIZE = 0x600L;

	private static final long BIOS_SIZE = 0x20000L;

	/** Battery RAM is 8 KiB answered across a window sixteen times its byte width. */
	private static final long BRAM_SIZE = 0x2000L;
	private static final long BRAM_WINDOW = 0x10000L;
	private static final long BRAM_ADDRESS = 0xFE0000L;

	private static final long PCM_WINDOW = 0x8000L;

	/** Word index into the ASIC's register file, and the name the hardware gives that register. */
	/**
	 * Word address in the boot ROM, and the name the sheet of the boot stage gives that entry. A
	 * disc calls the ROM through these, so marking them is what makes a call readable.
	 */
	private static final String[][] BIOS_ENTRIES_FOR_MAIN = {
		{ "280", "_bios_reset", "" },
		{ "284", "_bios_entry", "" },
		{ "288", "_bios_init", "" },
		{ "28c", "_bios_init_sp", "start the program of the drive" },
		{ "290", "_bios_vint", "the interrupt of the frame" },
		{ "294", "_bios_set_hint", "" },
		{ "298", "_bios_poll_io", "" },
		{ "29c", "_bios_detect_io", "" },
		{ "2a0", "_bios_clear_vram", "" },
		{ "2a4", "_bios_clear_nmtbl", "" },
		{ "2a8", "_bios_clear_vsram", "" },
		{ "2ac", "_bios_init_vdp", "" },
		{ "2b0", "_bios_vdp_loadregs", "" },
		{ "2b4", "_bios_vdp_fill", "" },
		{ "2b8", "_bios_clear_vram_range", "" },
		{ "2bc", "_bios_clear_vram_range_dma", "" },
		{ "2c0", "_bios_vram_dma_fill", "" },
		{ "2c4", "_bios_update_nmtbl", "" },
		{ "2c8", "_bios_update_nmtbl_template", "" },
		{ "2cc", "_bios_fill_nmtbl", "" },
		{ "2d0", "_bios_vdp_dma", "" },
		{ "2d4", "_bios_vdp_dma_wordram", "move a picture from the word RAM of the ASIC to the VDP" },
		{ "2d8", "_bios_vdp_display_enable", "" },
		{ "2dc", "_bios_vdp_display_disable", "" },
		{ "2e0", "_bios_pal_buffer", "" },
		{ "2e4", "_bios_pal_buffer_update", "" },
		{ "2e8", "_bios_pal_dma", "" },
		{ "2ec", "_bios_gfx_decomp", "the tiles a disc ships compressed" },
		{ "2f0", "_bios_gfx_decomp_ram", "" },
		{ "2f4", "_bios_update_sprites", "" },
		{ "2f8", "_bios_clear_ram", "the whole of work RAM, which a disc program lives in" },
		{ "300", "_bios_display_sprite", "" },
		{ "304", "_bios_wait_vint", "" },
		{ "308", "_bios_wait_vint_flags", "" },
		{ "30c", "_bios_dma_sat", "" },
		{ "314", "_bios_set_hint_direct", "" },
		{ "318", "_bios_disable_hint", "" },
		{ "31c", "_bios_print", "the only drawing of letters the boot stage offers" },
		{ "320", "_bios_load_user_font", "" },
		{ "324", "_bios_load_bios_font", "" },
		{ "328", "_bios_load_bios_font_default", "" },
		{ "338", "_bios_prng_mod", "" },
		{ "33c", "_bios_prng", "" },
		{ "340", "_bios_clear_comm", "the two queues of words the processors exchange" },
		{ "344", "_bios_comm_update", "" },
		{ "364", "_bios_sega_logo", "the screen the console shows before the disc" },
		{ "368", "_bios_set_vint", "" },
	};

	/**
	 * Address in program RAM, and the name of the routine the decompressed boot stage of the drive
	 * leaves there. The program of a disc reaches the ASIC through these.
	 */
	private static final String[][] BIOS_ENTRIES_FOR_SUB = {
		{ "5e80", "bios_common_work", "the workspace the routines below keep their state in" },
		{ "5f0a", "_setjmptbl", "point the table below at the routines of the disc" },
		{ "5f10", "_waitvsync", "" },
		{ "5f16", "_buram", "the battery RAM, read or written across its window" },
		{ "5f1c", "_cdboot", "carry a piece of the disc to memory" },
		{ "5f22", "_cdbios", "ask the drive something of its own" },
		{ "5f28", "_usercall0", "the four entries a disc program may replace" },
		{ "5f2e", "_usercall1", "" },
		{ "5f34", "_usercall2", "" },
		{ "5f3a", "_usercall3", "" },
		{ "5f40", "_adrerr", "the exceptions the drive reports to the console" },
		{ "5f46", "_coderr", "" },
		{ "5f4c", "_diverr", "" },
		{ "5f52", "_chkerr", "" },
		{ "5f58", "_trperr", "" },
		{ "5f5e", "_spverr", "" },
		{ "5f64", "_trace", "" },
		{ "5f6a", "_nocod0", "" },
		{ "5f70", "_nocod1", "" },
		{ "5f76", "_slevel1", "the interrupts at the three levels the drive answers at" },
		{ "5f7c", "_slevel2", "" },
		{ "5f82", "_slevel3", "" },
	};

	private static final String[][] GATE_ARRAY_REGISTERS = {
		{ "0", "GA_SUB_CPU_CTRL",
			"sub CPU control: interrupt enable and flag, the drive's LEDs, bus request, reset" },
		{ "1", "GA_MEM_MODE", "which processor holds program RAM and word RAM, and who may write them" },
		{ "2", "GA_CDC_CTRL", "direction and status of the transfers the drive makes" },
		{ "3", "GA_CDC_REG_DATA", "the drive's register port; the cartridge side reads its HINT vector here" },
		{ "4", "GA_CDC_HOST_DATA", "the drive's data port, one word per access" },
		{ "5", "GA_CDC_DMA_ADDR", "where a transfer from the drive lands" },
		{ "6", "GA_STOP_WATCH", "the disc clock, read as minutes, seconds and frames" },
		{ "7", "GA_COMM_FLAG", "the handshake between the two processors" },

		{ "8", "GA_COMM_CMD0", "the eight words the cartridge side puts in front of the drive side" },
		{ "9", "GA_COMM_CMD1", "" },
		{ "10", "GA_COMM_CMD2", "" },
		{ "11", "GA_COMM_CMD3", "" },
		{ "12", "GA_COMM_CMD4", "" },
		{ "13", "GA_COMM_CMD5", "" },
		{ "14", "GA_COMM_CMD6", "" },
		{ "15", "GA_COMM_CMD7", "" },

		{ "16", "GA_COMM_STATUS0", "the eight words the drive side answers with" },
		{ "17", "GA_COMM_STATUS1", "" },
		{ "18", "GA_COMM_STATUS2", "" },
		{ "19", "GA_COMM_STATUS3", "" },
		{ "20", "GA_COMM_STATUS4", "" },
		{ "21", "GA_COMM_STATUS5", "" },
		{ "22", "GA_COMM_STATUS6", "" },
		{ "23", "GA_COMM_STATUS7", "" },

		{ "24", "GA_TIMER", "the one second timer" },
		{ "25", "GA_INT_MASK", "interrupt enables of the cartridge side" },
		{ "26", "GA_CDD_FADER", "the volume and balance the drive reports" },
		{ "27", "GA_CDD_CTRL", "commands sent to the drive's own processor" },

		{ "28", "GA_CDD_STATUS0", "the five words the drive's processor reports" },
		{ "29", "GA_CDD_STATUS1", "" },
		{ "30", "GA_CDD_STATUS2", "" },
		{ "31", "GA_CDD_STATUS3", "" },
		{ "32", "GA_CDD_STATUS4", "" },

		{ "33", "GA_CDD_CMD0", "the five words a command to the drive is made of" },
		{ "34", "GA_CDD_CMD1", "" },
		{ "35", "GA_CDD_CMD2", "" },
		{ "36", "GA_CDD_CMD3", "" },
		{ "37", "GA_CDD_CMD4", "" },

		{ "38", "GA_FONT_COLOR", "colour of the font the ASIC draws on screen" },
		{ "39", "GA_FONT_BITS", "" },
		{ "40", "GA_FONT_DATA0", "the four words of one glyph" },
		{ "41", "GA_FONT_DATA1", "" },
		{ "42", "GA_FONT_DATA2", "" },
		{ "43", "GA_FONT_DATA3", "" },

		{ "128", "GA_SUBCODE", "the queue of subcode bytes read off the disc" },
	};

	/** True for the processor the drive itself runs, false for the one the console runs. */
	abstract boolean isSubCpu();

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
		CdImage disc = CdImage.open(provider, new MessageLog());
		if (disc == null) {
			return List.of();
		}

		try {
			return List.of(new LoadSpec(this, 0,
				new LanguageCompilerSpecPair(M68K_LANGUAGE_ID, "default"), true));
		}
		finally {
			disc.close();
		}
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

		new CdMemoryMap(program, settings, isSubCpu(), getName()).build();
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {

		List<Option> options = super.getDefaultOptions(provider, loadSpec, domainObject,
			loadIntoProgram, mirrorFsLayout);
		options.add(new Option(SegaLoadOptions.NAME_HW_REGISTERS, true, Boolean.class,
			SegaLoadOptions.ARG_HW_REGISTERS));
		options.add(new Option(SegaLoadOptions.NAME_VERIFY, true, Boolean.class,
			SegaLoadOptions.ARG_VERIFY));
		options.add(new Option(NAME_BIOS_FILE, "", String.class, ARG_BIOS_FILE));
		options.add(new Option(NAME_BRAM_FILE, "", String.class, ARG_BRAM_FILE));
		return options;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {

		for (String name : List.of(NAME_BIOS_FILE, NAME_BRAM_FILE)) {
			String path = SegaLoadOptions.getString(options, name);
			if (path != null && !new File(path).isFile()) {
				return name + ": no such file: " + path;
			}
		}

		return null;
	}

	/**
	 * The address space one processor of one disc gets. Exists per load, so that the loader itself
	 * stays stateless.
	 */
	private static class CdMemoryMap {

		private final Program program;
		private final String loaderName;
		private final MessageLog log;
		private final TaskMonitor monitor;
		private final FlatProgramAPI fpa;
		private final Memory memory;
		private final CdImage disc;
		private final boolean subCpu;

		private final boolean hardwareRegisters;
		private final boolean verify;
		private final String biosFile;
		private final String bramFile;

		private CdHeader header;
		private String headerPlate = "";

		CdMemoryMap(Program program, ImporterSettings settings, boolean subCpu, String loaderName)
				throws IOException {

			this.program = program;
			this.loaderName = loaderName;
			this.log = settings.log();
			this.monitor = settings.monitor();
			this.fpa = new FlatProgramAPI(program, monitor);
			this.memory = program.getMemory();
			this.subCpu = subCpu;
			this.disc = CdImage.open(settings.provider(), log);

			List<Option> options = settings.options();
			this.hardwareRegisters =
				SegaLoadOptions.getBoolean(options, SegaLoadOptions.NAME_HW_REGISTERS, true);
			this.verify = SegaLoadOptions.getBoolean(options, SegaLoadOptions.NAME_VERIFY, true);
			this.biosFile = SegaLoadOptions.getString(options, NAME_BIOS_FILE);
			this.bramFile = SegaLoadOptions.getString(options, NAME_BRAM_FILE);
		}

		void build() throws IOException, CancelledException {
			monitor.setMessage(String.format("%s : Start loading", loaderName));

			if (disc == null) {
				// The importer only gets this far after the loader recognized a disc.
				log.appendMsg("neither these bytes nor the file they point at are a readable disc");
				return;
			}

			log.appendMsg(String.format("%s : %s, %d byte sectors, %d KiB of user data", loaderName,
				disc.getFileName(), disc.sectorBytes(), disc.userDataBytes() / 1024));

			readHeader();

			if (subCpu) {
				buildDriveView();
			}
			else {
				buildCartridgeView();
			}

			monitor.setMessage(String.format("%s : Loading done", loaderName));
		}

		/**
		 * The header describes the disc instead of either processor's memory, so it is read and
		 * reported rather than placed: what a program needs of it reaches it through the ASIC and
		 * the boot stage, and this module does not guess an address for it.
		 */
		private void readHeader() throws IOException {
			byte[] raw = disc.readUserData(0, CdHeader.SIZE);
			if (raw.length < CdHeader.SIZE) {
				log.appendMsg("the disc is too short to carry its 512 byte header");
				return;
			}

			header = new CdHeader(new BinaryReader(new BytesProvider(raw), true), 0);

			StringBuilder plate = new StringBuilder();
			plate.append(String.format("%s  %s  %s\n%s  released %s\n", header.systemName(),
				header.versionInfo(), header.regions(), header.deviceInfo(), header.releaseDate()));
			plate.append(String.format("drive program 0x%X bytes at disc offset 0x%X\n",
				header.subProgram().length(), header.subProgram().discAddress()));
			plate.append(String.format("cartridge program 0x%X bytes at disc offset 0x%X",
				header.mainProgram().length(), header.mainProgram().discAddress()));
			headerPlate = plate.toString();

			log.appendMsg(headerPlate.replace("\n", "; ").trim());

			if (verify) {
				verifyHeader();
			}
		}

		private void verifyHeader() {
			if (!CdImage.SIGNATURE.equals(header.systemName())) {
				reportProblem("the first sector does not open with " + CdImage.SIGNATURE);
			}

			CdHeader.Program area = header.subProgram();
			if (area.isPresent()) {
				if (area.discAddress() < CdHeader.SIZE) {
					reportProblem(String.format(
						"the program of the drive is declared at disc offset 0x%X, inside the header sector itself",
						area.discAddress()));
				}
				else if (area.discAddress() + area.length() > disc.userDataBytes()) {
					reportProblem(String.format(
						"a program of 0x%X bytes at disc offset 0x%X runs past the %d KiB the disc holds",
						area.length(), area.discAddress(), disc.userDataBytes() / 1024));
				}
			}
		}

		/**
		 * The drive's own processor holds all of program RAM, the word RAM through two windows, and
		 * the sound memory, the battery RAM and the ASIC at the top of its address space.
		 */
		private void buildDriveView() throws IOException {
			byte[] code = readProgram(header == null ? null : header.subProgram(),
				PROG_RAM_SIZE - PROG_RAM_PROGRAM_OFFSET, "drive");

			ramBlock("PROGRAM_RAM", 0L, PROG_RAM_PROGRAM_OFFSET,
				"the low program RAM, where the boot stage keeps the vectors and workspace this processor starts from",
				false);
			createBiosEntries(BIOS_ENTRIES_FOR_SUB);

			long free = placeProgram("DISC_PROGRAM", PROG_RAM_PROGRAM_OFFSET, code, true);
			ramBlock("PROGRAM_RAM_FREE", free, PROG_RAM_SIZE - free,
				"the rest of program RAM, left to the program above and to the transfers the drive makes",
				false);

			ramBlock("WORD_RAM", 0x80000L, 0x40000L,
				"the ASIC's word RAM, reached through the window that shows two hundred fifty six KiB of it",
				false);
			ramBlock("WORD_RAM_1M", 0xC0000L, 0x20000L,
				"the same word RAM through the window that shows only its first half", false);

			createBackupRam();

			ramBlock("PCM", 0xFF0000L, PCM_WINDOW,
				"the sound memory and control of the RF5C164, answered on odd byte addresses only",
				true);

			if (hardwareRegisters) {
				createGateArray(0xFF8000L);
				createPcmRegisters();
			}

			if (code != null) {
				markDiscEntries(PROG_RAM_PROGRAM_OFFSET, code);
			}
		}

		/**
		 * The processor of the cartridge side is shown the boot ROM where a cartridge would sit and
		 * the low program RAM after it, the word RAM through its own windows, the ASIC in the port
		 * region a cartridge gives to a floppy controller, and the console's work RAM with the
		 * program that booted with the disc already in it.
		 */
		private void buildCartridgeView() throws IOException {
			MemoryBlock bios = createBios();
			if (bios != null) {
				// The ASIC shows the boot ROM a second time, right above program RAM.
				mirrorBlock("BIOS_ROM", 0L, 0x40000L, BIOS_SIZE);
				createBiosEntries(BIOS_ENTRIES_FOR_MAIN);
			}

			byte[] driveCode = readProgram(header == null ? null : header.subProgram(),
				PROG_WINDOW_SIZE_FOR_MAIN - PROG_RAM_PROGRAM_OFFSET, "drive");

			ramBlock("PROGRAM_RAM", PROG_WINDOW_FOR_MAIN, PROG_RAM_PROGRAM_OFFSET,
				"the low program RAM, shared with the drive's processor", false);
			long free = placeProgram("DISC_PROGRAM", PROG_WINDOW_FOR_MAIN + PROG_RAM_PROGRAM_OFFSET,
				driveCode, true);
			ramBlock("PROGRAM_RAM_FREE", free,
				PROG_WINDOW_FOR_MAIN + PROG_WINDOW_SIZE_FOR_MAIN - free,
				"program RAM this processor reaches through the window, past the program", false);

			ramBlock("WORD_RAM", 0x200000L, 0x20000L,
				"the ASIC's word RAM, whose bank the gate array selects", false);
			ramBlock("CELL_IMAGE", 0x220000L, 0x20000L,
				"the window of the word RAM the ASIC draws its on screen font from", false);

			if (hardwareRegisters) {
				createGateArray(0xA12000L);
				MegaDriveRegisters.create(program, fpa, log, loaderName, false, true);
			}

			byte[] bootCode = bootProgram();
			long placed = placeProgram("BOOT_PROGRAM", WORK_RAM_ADDRESS, bootCode, true);
			if (placed < WORK_RAM_ADDRESS + WORK_RAM_SIZE) {
				ramBlock("WORK_RAM_FREE", placed, WORK_RAM_ADDRESS + WORK_RAM_SIZE - placed,
					"the work RAM of the console, past what the disc put in it", false);
			}

			if (bootCode != null && bootCode.length > 0) {
				createFunction(WORK_RAM_ADDRESS, "BOOT_entry");
			}
		}

		/**
		 * The program the console runs on its own. Its place on the disc and in memory is fixed: the
		 * boot stage takes the first program area from inside the header sector and puts it at the
		 * bottom of work RAM, where it then asks the drive for the rest of the game. The header
		 * carries a second pair of program fields, whose meaning no disc uses as an address the
		 * console reads from; a disc that fills them with something else than the fixed place is
		 * reported and believed no further than that.
		 */
		private byte[] bootProgram() throws IOException {
			CdHeader.Program area = header == null ? null : header.mainProgram();
			if (area != null && area.isPresent() && area.discAddress() != BOOT_PROGRAM_DISC_OFFSET) {
				log.appendMsg(String.format(
					"the header pairs 0x%X with the processor of the cartridge side, whose program is taken from disc offset 0x%X either way",
					area.discAddress(), BOOT_PROGRAM_DISC_OFFSET));
			}

			return readProgram(new CdHeader.Program(BOOT_PROGRAM_DISC_OFFSET, BOOT_PROGRAM_SIZE),
				BOOT_PROGRAM_SIZE, "cartridge");
		}

		/** The bytes of one declared area, cut to what the disc holds and to the memory it lands in. */
		private byte[] readProgram(CdHeader.Program area, long room, String owner)
				throws IOException {

			if (area == null || !area.isPresent()) {
				log.appendMsg(String.format(
					"the disc declares no program for its %s processor, so none is placed", owner));
				return null;
			}

			int length = (int) Math.min(area.length(), room);
			byte[] code = disc.readUserData(area.discAddress(), length);
			if (code.length == 0) {
				log.appendMsg(String.format(
					"the %s program at disc offset 0x%X cannot be read, nothing placed for it", owner,
					area.discAddress()));
				return null;
			}
			if (code.length < length) {
				log.appendMsg(String.format("only 0x%X of the 0x%X byte(s) the %s program promises",
					code.length, length, owner));
			}

			return code;
		}

		/**
		 * The bytes of a disc program, in the memory the processor that runs them sees. Returns the
		 * address after the block, which is where the memory that is not a program begins.
		 */
		private long placeProgram(String name, long address, byte[] code, boolean write)
				throws IOException {

			if (code == null || code.length == 0) {
				return address;
			}

			initializedBlock(name, address, code,
				String.format("%s, marked %s%n%s", markerOf(code), name, headerPlate), write, true,
				false);

			return address + code.length;
		}

		/** Bytes given to a block of their own, reported the way the importer reports a block. */
		private void initializedBlock(String name, long address, byte[] data, String comment,
				boolean write, boolean execute, boolean volatileBlock) {

			try {
				MemoryBlock block = MemoryBlockUtils.createInitializedBlock(program, false, name,
					toAddr(address), new ByteArrayInputStream(data), data.length, comment, loaderName,
					true, write, execute, log, monitor);
				if (block != null && volatileBlock) {
					block.setVolatile(true);
				}
			}
			catch (AddressOverflowException e) {
				log.appendException(e);
			}
		}

		/**
		 * The boot stage marks the head of every program with the processor it runs on and the
		 * version of the sheet it was made from, which is the only thing that tells the two of them
		 * apart once they are out of the header.
		 */
		private String markerOf(byte[] code) {
			if (code.length < 16) {
				return "no header of its own";
			}

			StringBuilder marker = new StringBuilder();
			for (int i = 0; i < 16; i++) {
				char c = (char) (code[i] & 0xff);
				marker.append(c > ' ' && c <= '~' ? c : ' ');
			}
			return "'" + marker.toString().trim() + "'";
		}

		/**
		 * A program of the drive announces the routines the boot stage calls: the word at 0x18 gives
		 * the offset of a table of words, each of them the offset of a routine from the head of that
		 * table. Three of them have names the boot stage gives them, the rest are numbered.
		 */
		private void markDiscEntries(long loadAddress, byte[] code) {
			if (code.length < 0x1a) {
				return;
			}

			int table = unsignedWord(code, 0x18);
			if (table <= 0 || table + 2 > code.length) {
				log.appendMsg(
					"the program of the drive declares no table of routines, its entry stays unmarked");
				return;
			}

			String[] known = { "DISC_init", "DISC_main", "DISC_int2" };
			for (int index = 0; index < 16 && table + index * 2 + 1 < code.length; index++) {
				int offset = unsignedWord(code, table + index * 2);
				long entry = loadAddress + table + offset;
				if (offset == 0 || entry >= loadAddress + code.length) {
					break;
				}

				String name = index < known.length ? known[index] : "DISC_usercall" + index;
				createFunction(entry, name);
			}
		}

		/**
		 * The routines the boot stage of the drive answers to, and the entries of the boot ROM a
		 * console program calls, named where the hardware puts them. They are only labels: the
		 * memory of the boot stage is not something a disc image can supply, and the ROM only when
		 * its file was given.
		 */
		private void createBiosEntries(String[][] entries) {
			for (String[] entry : entries) {
				Address at = toAddr(Long.parseLong(entry[0], 16));
				label(at, entry[1]);
				if (!entry[2].isEmpty()) {
					program.getListing().setComment(at, CommentType.PRE, entry[2]);
				}
			}
		}

		private static int unsignedWord(byte[] code, int offset) {
			return (code[offset] & 0xff) << 8 | code[offset + 1] & 0xff;
		}

		/**
		 * The boot ROM is what the console runs before anything of the disc, and the vectors it
		 * gives a disc are read from it, so it is placed where the ASIC maps it and left without
		 * bytes when its file was not given.
		 */
		private MemoryBlock createBios() throws IOException {
			if (biosFile == null) {
				ramBlock("BIOS_ROM", 0L, BIOS_SIZE,
					"the CD boot ROM the console runs first; the loader option names its file", true);
				return null;
			}

			byte[] bios = Files.readAllBytes(Path.of(biosFile));
			int size = (int) Math.min(bios.length, BIOS_SIZE);
			if (size != bios.length) {
				log.appendMsg(String.format(
					"%s holds %d byte(s); the ASIC maps 128 KiB, the %d byte(s) above it are not reachable",
					biosFile, bios.length, bios.length - size));
			}

			initializedBlock("BIOS_ROM", 0L, bios,
				String.format("%s, the boot ROM the console runs before the disc", biosFile), false,
				true, false);

			return size == 0 ? null : memory.getBlock(toAddr(0L));
		}

		/**
		 * Battery RAM is 8 KiB answered on odd addresses across a window of sixteen times that, so
		 * a save is spread over the window it fills instead of written into it in order.
		 */
		private void createBackupRam() throws IOException {
			byte[] save = bramFile == null ? null : Files.readAllBytes(Path.of(bramFile));
			int length = save == null ? 0 : (int) Math.min(save.length, BRAM_SIZE);

			if (length > 0) {
				byte[] spread = new byte[length * 2];
				for (int i = 0; i < length; i++) {
					spread[i * 2 + 1] = save[i];
				}

				initializedBlock("BACKUP_RAM", BRAM_ADDRESS, spread, String.format(
					"%s, %d byte(s) of battery RAM on the odd addresses of its window", bramFile,
					length), true, false, true);
			}

			if (length * 2 < BRAM_WINDOW) {
				ramBlock(length > 0 ? "BACKUP_RAM_FREE" : "BACKUP_RAM", BRAM_ADDRESS + length * 2,
					BRAM_WINDOW - length * 2,
					"the rest of the window, across which the battery RAM answers again", true);
			}
		}

		private void createGateArray(long base) {
			MemoryBlock block = MemoryBlockUtils.createUninitializedBlock(program, false,
				"GATE_ARRAY", toAddr(base), 0x200,
				"the ASIC registers; every address above the last of them repeats these 512 bytes",
				loaderName, true, true, false, log);
			if (block != null) {
				block.setVolatile(true);
			}

			for (String[] register : GATE_ARRAY_REGISTERS) {
				long index = Long.parseLong(register[0]);
				createNamedData(base + 2 * index, register[1], WordDataType.dataType,
					register[2].isEmpty() ? null : register[2]);
			}

			label(toAddr(base + 0x180), "GA_SUBCODE_MIRROR");
		}

		/**
		 * The sound chip is reached through odd byte addresses only, and its eight channels share
		 * one set of registers chosen by a write to the control port.
		 */
		private void createPcmRegisters() {
			String[][] registers = {
				{ "PCM_CHANNEL_ENVELOPE", "the register of the channel the control port selected" },
				{ "PCM_CHANNEL_PAN", "" },
				{ "PCM_CHANNEL_FREQ_LOW", "" },
				{ "PCM_CHANNEL_FREQ_HIGH", "" },
				{ "PCM_CHANNEL_LOOP_LOW", "" },
				{ "PCM_CHANNEL_LOOP_HIGH", "" },
				{ "PCM_CHANNEL_START", "" },
				{ "PCM_CONTROL", "start sounding, choose a channel, choose a memory bank" },
				{ "PCM_CHANNEL_ENABLE", "one bit per channel" },
			};

			for (int index = 0; index < registers.length; index++) {
				String comment = registers[index][1];
				createNamedData(0xFF0000L + 2L * index + 1, registers[index][0],
					ByteDataType.dataType, comment.isEmpty() ? null : comment);
			}

			label(toAddr(0xFF2001L), "PCM_WAVE_RAM");
		}

		private void ramBlock(String name, long address, long size, String comment,
				boolean volatileBlock) {

			MemoryBlock block = MemoryBlockUtils.createUninitializedBlock(program, false, name,
				toAddr(address), size, comment, loaderName, true, true, !volatileBlock, log);
			if (block != null && volatileBlock) {
				// Ghidra would otherwise drop the writes a program makes to hardware it never reads.
				block.setVolatile(true);
			}
		}

		/** Alias of an existing block at another address, sharing its bytes. */
		private void mirrorBlock(String name, long physicalAddress, long mappedAddress, long size) {
			try {
				MemoryBlock block =
					memory.createByteMappedBlock(name, toAddr(mappedAddress),
						toAddr(physicalAddress), size, false);
				MemoryBlock physical = memory.getBlock(toAddr(physicalAddress));
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

		private void createNamedData(long address, String name, DataType type, String comment) {
			try {
				fpa.createData(toAddr(address), type);
			}
			catch (Exception e) {
				log.appendMsg(name + ": " + e.getMessage());
			}

			Address at = toAddr(address);
			label(at, name);
			if (comment != null) {
				program.getListing().setComment(at, CommentType.PRE, comment);
			}
		}

		private void createFunction(long address, String name) {
			Address at = toAddr(address);
			fpa.createFunction(at, name);

			Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
			AutoAnalysisManager.getAnalysisManager(program)
					.codeDefined(dis.disassemble(at, null, false));
		}

		private void reportProblem(String message) {
			log.appendMsg(message);
			program.getBookmarkManager().setBookmark(toAddr(0L), BookmarkType.WARNING,
				"Sega CD disc", message);
		}

		private void label(Address address, String name) {
			try {
				program.getSymbolTable().createLabel(address, name, SourceType.IMPORTED);
			}
			catch (Exception e) {
				log.appendException(e);
			}
		}

		private Address toAddr(long offset) {
			return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
		}
	}

	/** The header of a disc is read out of a sector, so it is handed over as plain bytes. */
	private static class BytesProvider implements ByteProvider {

		private final byte[] data;

		BytesProvider(byte[] data) {
			this.data = data;
		}

		@Override
		public String getName() {
			return "disc header";
		}

		@Override
		public String getAbsolutePath() {
			return getName();
		}

		@Override
		public File getFile() {
			return null;
		}

		@Override
		public long length() {
			return data.length;
		}

		@Override
		public boolean isValidIndex(long index) {
			return index >= 0 && index < data.length;
		}

		@Override
		public void close() throws IOException {
		}

		@Override
		public byte readByte(long index) throws IOException {
			if (!isValidIndex(index)) {
				throw new IOException("index out of bounds: " + index);
			}
			return data[(int) index];
		}

		@Override
		public byte[] readBytes(long index, long length) throws IOException {
			if (index < 0 || length < 0 || index + length > data.length) {
				throw new IOException("bytes out of bounds: " + index + " + " + length);
			}

			byte[] bytes = new byte[(int) length];
			System.arraycopy(data, (int) index, bytes, 0, (int) length);
			return bytes;
		}
	}
}

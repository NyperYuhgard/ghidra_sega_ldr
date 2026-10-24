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
import ghidra.program.database.mem.FileBytes;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
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
 * Loader for Sega Master System and Game Gear cartridges. The Z80 only ever sees 64 KiB, so the
 * image is placed the way the console sees it at power on: the first three 16 KiB pages in order,
 * the rest of the cartridge reachable through the mapper as overlays of the last window, and the
 * IO ports in the language's own {@code io} space.
 */
public class SegaSmsLoader extends AbstractProgramLoader {

	public static final String LOADER_NAME = "Sega Master System / Game Gear Loader";

	private static final String Z80_LANGUAGE_ID = "z80:LE:16:default";

	private static final String NAME_CART_RAM_FILE = "Cartridge RAM contents file (.sav / .sms)";
	private static final String ARG_CART_RAM_FILE =
		Loader.COMMAND_LINE_ARG_PREFIX + "-cart-ram-file";

	/** Size of one mapper window, and the address of the window the mapper moves. */
	private static final long BANK_SIZE = 0x4000L;
	private static final long BANK_WINDOW = 0x8000L;

	/** The two pages that stay put: 0x0000-0x7fff of a banked cartridge is file offset 0. */
	private static final long LINEAR_SIZE = 0x8000L;

	/** System RAM holds 8 KiB, mirrored over the top 16 KiB of the address space. */
	private static final long SYSTEM_RAM_SIZE = 0x2000L;
	private static final long RAM_MIRROR = 0xe000L;
	private static final long MAPPER_REGISTERS = 0xfffcL;

	private static final long RESET_VECTOR = 0x0L;
	private static final long NMI_VECTOR = 0x66L;
	private static final long RST_FIRST = 0x8L;
	private static final long RST_LAST = 0x38L;

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
		if (SmsHeader.find(new BinaryReader(provider, true)) < 0) {
			return List.of();
		}
		return List.of(new LoadSpec(this, 0,
			new LanguageCompilerSpecPair(Z80_LANGUAGE_ID, "default"), true));
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
		new SmsMemoryMap(program, settings).build();
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
		options.add(new Option(NAME_CART_RAM_FILE, "", String.class, ARG_CART_RAM_FILE));
		return options;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {

		String path = SegaLoadOptions.getString(options, NAME_CART_RAM_FILE);
		if (path == null) {
			return null;
		}

		try {
			if (!Files.isRegularFile(Path.of(path))) {
				return NAME_CART_RAM_FILE + ": no such file: " + path;
			}
		}
		catch (InvalidPathException e) {
			return NAME_CART_RAM_FILE + ": " + path;
		}

		return null;
	}

	/**
	 * The 64 KiB view one cartridge image gets. Exists per load so that the loader itself stays
	 * stateless.
	 */
	private static class SmsMemoryMap {

		private final Program program;
		private final MessageLog log;
		private final TaskMonitor monitor;
		private final BinaryReader reader;

		private final FlatProgramAPI fpa;
		private final Memory memory;
		private final AddressSpace ram;
		private final AddressSpace io;

		private final FileBytes romBytes;
		private final long romLength;

		private final boolean hardwarePorts;
		private final boolean verify;
		private final String cartRamFile;

		private long headerOffset;
		private SmsHeader header;
		private boolean gameGear;

		SmsMemoryMap(Program program, ImporterSettings settings)
				throws IOException, CancelledException {
			this.program = program;
			this.log = settings.log();
			this.monitor = settings.monitor();
			this.reader = new BinaryReader(settings.provider(), true);
			this.fpa = new FlatProgramAPI(program, monitor);
			this.memory = program.getMemory();
			this.ram = program.getAddressFactory().getDefaultAddressSpace();
			this.io = program.getAddressFactory().getAddressSpace("io");
			this.romBytes =
				MemoryBlockUtils.createFileBytes(program, settings.provider(), monitor);
			this.romLength = settings.provider().length();

			List<Option> options = settings.options();
			this.hardwarePorts =
				SegaLoadOptions.getBoolean(options, SegaLoadOptions.NAME_HW_REGISTERS, true);
			this.verify = SegaLoadOptions.getBoolean(options, SegaLoadOptions.NAME_VERIFY, true);
			this.cartRamFile = SegaLoadOptions.getString(options, NAME_CART_RAM_FILE);
		}

		void build() throws IOException, CancelledException {
			monitor.setMessage(String.format("%s : Start loading", LOADER_NAME));

			headerOffset = SmsHeader.find(reader);
			if (headerOffset >= 0) {
				header = new SmsHeader(reader, headerOffset);
				gameGear = header.isGameGear();
			}

			createRom();
			createRam();
			if (hardwarePorts) {
				createPorts();
			}
			markEntryPoint();

			if (header != null) {
				markHeader();
				if (verify) {
					verifyHeader();
				}
			}
			else {
				log.appendMsg(
					"no \"TMR SEGA\" header at 0x7ff0, 0x3ff0 or 0x1ff0; region, checksum and mapper type are unknown");
			}

			monitor.setMessage(String.format("%s : Loading done", LOADER_NAME));
		}

		/**
		 * Power on leaves the first three pages of the cartridge in order, so that is the view:
		 * 0x0000-0x7fff holds file offset 0, and the window at 0x8000 is where the mapper moves the
		 * rest of the image. Those later pages are overlays, because the Z80 address space is only
		 * 64 KiB and there is nowhere else to put them.
		 */
		private void createRom() throws IOException {
			long linear = Math.min(romLength, LINEAR_SIZE);
			fileBlock("ROM", 0L, 0L, linear, true, false, true, false,
				"the first two pages of the cartridge, where the console starts");

			if (romLength <= LINEAR_SIZE) {
				if (romLength < LINEAR_SIZE) {
					log.appendMsg(String.format(
						"the console mirrors a %d KiB image over 0x%X-0xFFFF; only the 0x%X byte(s) the file holds are shown",
						romLength / 1024, LINEAR_SIZE, romLength));
				}
				return;
			}

			fileBlock("ROM_BANK2", BANK_WINDOW, LINEAR_SIZE, BANK_SIZE, true, false, true, false,
				"page 2: the window the mapper moves, left in place until the game writes to 0xFFFC");

			long available = romLength - LINEAR_SIZE - BANK_SIZE;
			int banks = (int) (available / BANK_SIZE);
			for (int i = 0; i < banks; i++) {
				long fileOffset = LINEAR_SIZE + BANK_SIZE * (i + 1);
				fileBlock("ROM_BANK" + (i + 3), BANK_WINDOW, fileOffset, BANK_SIZE, true, false,
					true, true, String.format("file offset 0x%X, paged in by a write to 0xFFFC",
						fileOffset));
			}

			long trailing = available % BANK_SIZE;
			if (trailing > 0) {
				long fileOffset = LINEAR_SIZE + BANK_SIZE * (banks + 1);
				fileBlock("ROM_BANK" + (banks + 3), BANK_WINDOW, fileOffset, trailing, true, false,
					true, true, String.format("file offset 0x%X, %d byte(s) short of a page",
						fileOffset, trailing));
			}

			if (banks > 0) {
				log.appendMsg(String.format(
					"%d more 16 KiB page(s) placed as overlays of 0x8000-0xBFFF; select the one a running game paged in from the memory map window",
					banks + (trailing > 0 ? 1 : 0)));
			}
		}

		private void createRam() throws IOException {
			Address ramStart = toAddr(ram, 0xC000L);
			MemoryBlock work = MemoryBlockUtils.createUninitializedBlock(program, false, "RAM",
				ramStart, SYSTEM_RAM_SIZE, "system RAM, the 8 KiB the console mirrors over 0xC000-0xFFFF",
				LOADER_NAME, true, true, false, log);
			if (work != null) {
				work.setVolatile(true);
			}

			mirrorBlock("RAM_ECHO", 0xC000L, RAM_MIRROR,
				MAPPER_REGISTERS - RAM_MIRROR);

			MemoryBlock mapper = MemoryBlockUtils.createUninitializedBlock(program, false,
				"MAPPER", toAddr(ram, MAPPER_REGISTERS), 4,
				"bank number of the three windows, written as bytes; the console ignores 0xFFFE",
				LOADER_NAME, true, true, false, log);
			if (mapper != null) {
				mapper.setVolatile(true);
			}
			createNamedByte(MAPPER_REGISTERS, "MAPPER_PAGE1");
			createNamedByte(MAPPER_REGISTERS + 1, "MAPPER_PAGE2");
			createNamedByte(MAPPER_REGISTERS + 3, "MAPPER_PAGE3");

			if (cartRamFile != null) {
				loadCartRam();
			}
		}

		/**
		 * Battery and extra RAM of a cartridge sit in the window the mapper moves, so the save is
		 * another overlay of it rather than a block of its own.
		 */
		private void loadCartRam() throws IOException {
			Path path = Path.of(cartRamFile);
			byte[] content = Files.readAllBytes(path);
			long size = Math.min(content.length, BANK_SIZE);

			Address start = toAddr(ram, BANK_WINDOW);
			MemoryBlock block;
			try {
				block = memory.createInitializedBlock("CART_RAM", start, size, (byte) 0, monitor,
					true);
			}
			catch (LockException | MemoryConflictException | AddressOverflowException
					| IllegalArgumentException | CancelledException e) {
				log.appendException(e);
				return;
			}

			block.setRead(true);
			block.setWrite(true);
			block.setExecute(false);
			block.setVolatile(true);
			block.setComment(String.format("%s, %d byte(s) of cartridge RAM", path, content.length));

			try {
				memory.setBytes(start, content, 0, (int) size);
			}
			catch (MemoryAccessException e) {
				log.appendException(e);
			}
		}

		/**
		 * Ports named in the Z80 language's IO space. The Sleigh decoder turns an immediate port
		 * number into a constant, so these do not collect references from the code; they are here
		 * so that a port read in a disassembly has a name and a type when it is found.
		 */
		private void createPorts() {
			portBlock("VDP", 0x80, 0x40, "data port on even addresses, control and status on odd");
			portRegister(0xBE, "VDP_DATA");
			portRegister(0xBF, "VDP_CTRL");

			portBlock("PSG", 0x40, 0x40,
				"writes reach the tone generator, reads return the latched raster position");
			portRegister(0x7F, "PSG_WRITE");
			portRegister(0x40, "HV_COUNTER_H");
			portRegister(0x41, "HV_COUNTER_V");

			portBlock("CONTROLLER", 0xC0, 0x40,
				"two controller ports read back on 0xC0 and 0xDC, control on 0xC1 and 0xDD");
			portRegister(0xDC, "IO_DATA_AB");
			portRegister(0xDD, "IO_CTRL");
			portRegister(0xC0, "IO_DATA_AB_ALT");
			portRegister(0xC1, "IO_CTRL_ALT");

			if (gameGear) {
				portBlock("GG_IO", 0x00, 0x07,
					"start and region, second controller port, serial link and stereo panel");
				portRegister(0x00, "GG_START_REGION");
				portRegister(0x01, "GG_IO_DATA");
				portRegister(0x02, "GG_IO_CTRL");
				portRegister(0x03, "GG_SERIAL_OUT");
				portRegister(0x04, "GG_SERIAL_RX");
				portRegister(0x05, "GG_SERIAL_CTRL");
				portRegister(0x06, "PSG_PAN");
				portBlock("IO_CONTROL", 0x08, 0x38,
					"controller latch and the pulse that makes the raster position update");
			}
			else {
				portBlock("IO_CONTROL", 0x00, 0x40,
					"controller latch and the pulse that makes the raster position update");
			}
		}

		private void portBlock(String name, long start, long size, String comment) {
			MemoryBlock block = MemoryBlockUtils.createUninitializedBlock(program, false, name,
				toAddr(io, start), size, comment, LOADER_NAME, true, true, false, log);
			if (block != null) {
				block.setVolatile(true);
			}
		}

		private void portRegister(long port, String name) {
			Address address = toAddr(io, port);
			try {
				DataUtilities.createData(program, address, ByteDataType.dataType, -1, false,
					ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			}
			catch (CodeUnitInsertionException e) {
				log.appendMsg(name + ": " + e.getMessage());
			}
			label(address, name);
		}

		/**
		 * The reset vector of these consoles holds nothing but a jump, and the Z80 language follows
		 * direct jumps on its own, so disassembling from 0 is enough to reach the program.
		 */
		private void markEntryPoint() {
			Address reset = toAddr(ram, RESET_VECTOR);
			Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
			AddressSetView disassembled = dis.disassemble(reset, null, false);
			AutoAnalysisManager.getAnalysisManager(program).codeDefined(disassembled);
			if (disassembled.isEmpty()) {
				// A header with garbage at 0 leaves nothing to follow; the analyzer needs the seed.
				AutoAnalysisManager.getAnalysisManager(program).codeDefined(new AddressSet(reset));
			}

			fpa.createFunction(toAddr(ram, NMI_VECTOR), "NMI_ISR");
			for (long vector = RST_FIRST; vector <= RST_LAST; vector += 8) {
				fpa.createFunction(toAddr(ram, vector), String.format("RST_%02X", vector));
			}
		}

		private void markHeader() {
			Address address = toAddr(ram, headerOffset);
			try {
				DataUtilities.createData(program, address, header.toDataType(), -1, false,
					ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			}
			catch (CodeUnitInsertionException e) {
				log.appendException(e);
				return;
			}

			label(address, "SMS_HEADER");

			program.getListing().setComment(address, CommentType.PLATE, String.format(
				"%s  version %d\nproduct %s  checksum 0x%04X over 0x%X\nROM %d KiB in %d page(s)",
				header.getRegionName(), header.getVersion(), header.getProductCode(),
				header.getChecksum(), header.getDeclaredRomSize(), romLength / 1024,
				Math.max(1, (int) (romLength / BANK_SIZE))));

			MemoryBlock rom = memory.getBlock("ROM");
			if (rom != null) {
				rom.setComment(String.format("%s, product %s", header.getRegionName(),
					header.getProductCode()));
			}
		}

		private void verifyHeader() throws IOException, CancelledException {
			long declared = header.getDeclaredRomSize();
			if (declared > 0 && declared != romLength) {
				reportProblem(headerOffset + 0xf, String.format(
					"the checksum range nibble describes a %d KiB ROM, the file is %d KiB",
					declared / 1024, romLength / 1024));
			}

			boolean codemasters = SmsHeader.hasCodemastersHeader(reader, headerOffset);
			int expected = SmsHeader.byteSum(reader, headerOffset,
				declared > 0 ? declared : romLength, monitor);
			int stored = header.getChecksum();

			if (codemasters) {
				int cmExpected = SmsHeader.codemastersWordSum(reader, headerOffset, monitor);
				int cmStored = (reader.readByte(headerOffset - 0xa) & 0xff)
					| ((reader.readByte(headerOffset - 0x9) & 0xff) << 8);
				if (cmStored == cmExpected) {
					log.appendMsg(String.format(
						"Codemasters checksum 0x%04X is correct, the mapper pages through writes to 0x0000, 0x4000 and 0x8000",
						cmStored));
				}
				else {
					reportProblem(headerOffset - 0xa, String.format(
						"Codemasters checksum is 0x%04X, the image adds up to 0x%04X", cmStored,
						cmExpected));
				}
			}

			if (stored == expected) {
				log.appendMsg(String.format("checksum 0x%04X is correct", stored));
			}
			else if (gameGear || header.getRegionNibble() == 0x3) {
				// Only the export Master System BIOS insists on a correct checksum.
				log.appendMsg(String.format(
					"checksum field holds 0x%04X, the ROM adds up to 0x%04X; %s does not check it",
					stored, expected, header.getRegionName()));
			}
			else {
				reportProblem(headerOffset + 0xa, String.format(
					"checksum is 0x%04X, the ROM adds up to 0x%04X; a patched ROM usually keeps the value of the image it was cut from",
					stored, expected));
			}
		}

		private void reportProblem(long offset, String message) {
			log.appendMsg(message);
			program.getBookmarkManager().setBookmark(toAddr(ram, offset), BookmarkType.WARNING,
				"Sega header", message);
		}

		/** Block backed by the image, clipped to what the file actually contains. */
		private void fileBlock(String name, long address, long fileOffset, long size, boolean read,
				boolean write, boolean execute, boolean overlay, String comment) {

			long available = fileOffset < romLength ? romLength - fileOffset : 0;
			long initialized = Math.min(size, available);

			try {
				if (initialized > 0) {
					MemoryBlockUtils.createInitializedBlock(program, overlay, name,
						toAddr(ram, address), romBytes, fileOffset, initialized, comment,
						LOADER_NAME, read, write, execute, log);
				}
				if (initialized < size) {
					MemoryBlockUtils.createUninitializedBlock(program, overlay,
						name + "_NO_DATA", toAddr(ram, address + initialized), size - initialized,
						"the image is shorter than the window it fills", LOADER_NAME, read, write,
						execute, log);
				}
			}
			catch (AddressOverflowException e) {
				log.appendException(e);
			}
		}

		/** Alias of an existing block at another address, sharing its bytes. */
		private void mirrorBlock(String name, long physicalAddress, long mappedAddress, long size) {
			try {
				MemoryBlock block =
					memory.createByteMappedBlock(name, toAddr(ram, mappedAddress),
						toAddr(ram, physicalAddress), size, false);
				MemoryBlock physical = memory.getBlock(toAddr(ram, physicalAddress));
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

		private void createNamedByte(long address, String name) {
			try {
				fpa.createByte(toAddr(ram, address));
			}
			catch (Exception e) {
				log.appendException(e);
			}
			label(toAddr(ram, address), name);
		}

		private void label(Address address, String name) {
			try {
				program.getSymbolTable().createLabel(address, name, SourceType.IMPORTED);
			}
			catch (InvalidInputException e) {
				log.appendException(e);
			}
		}

		private Address toAddr(AddressSpace space, long offset) {
			return space.getAddress(offset);
		}
	}
}

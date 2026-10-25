package sega;

import java.io.IOException;
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
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Loader for Sega SG-1000 and SC-3000 cartridges. Neither computer puts anything in front of a
 * cartridge: the image starts at 0 and the console mirrors it over its own 48 KiB window with the
 * mask of its size, so that is the view given here, with the 8 KiB of RAM above it echoed over the
 * top 16 KiB and the ports of each machine in the Z80 language's IO space.
 * <p>
 * <b>This support is not tested against a cartridge.</b> The map comes from the sources of an
 * emulator, and the machine is taken from the extension of the file because the image itself
 * carries nothing that says which computer it was made for.
 */
public class SegaSg1000Loader extends AbstractProgramLoader {

	public static final String LOADER_NAME = "Sega SG-1000 / SC-3000 Loader";

	/** Shown in the import log of every load, and in the comment of the ROM block. */
	static final String UNTESTED =
		"the SG-1000 and SC-3000 support of this extension is not tested against a real cartridge: "
			+ "the map comes from the emulator's sources, and the machine is chosen from the file "
			+ "extension because the image carries nothing that says which one it is for";

	private static final String Z80_LANGUAGE_ID = "z80:LE:16:default";

	/** The window the console decodes a cartridge in, and the mask of size it mirrors it with. */
	private static final long CART_WINDOW = 0xC000L;

	/** The 8 KiB of RAM, which the console echoes over its own top 16 KiB. */
	private static final long SYSTEM_RAM_START = 0xC000L;
	private static final long SYSTEM_RAM_SIZE = 0x2000L;
	private static final long RAM_ECHO_START = 0xE000L;

	/** The windows of the paging scheme an oversized image is pushed into, and its registers. */
	private static final long PAGED_FIRST = 0x400L;
	private static final long PAGED_SECOND = 0x4000L;
	private static final long PAGED_THIRD = 0x8000L;
	private static final long MAPPER_REGISTERS = 0xfffcL;

	/** How many echoes one program is given before the count stops being useful. */
	private static final int MAX_ECHOES = 16;

	private static final long NMI_VECTOR = 0x66L;
	private static final long RST_FIRST = 0x8L;
	private static final long RST_LAST = 0x38L;

	private enum Machine {
		SG_1000("SG-1000", "sg", "sg1"),
		SC_3000("SC-3000", "sc", "sf7", "sc3");

		private final String label;
		private final String[] extensions;

		Machine(String label, String... extensions) {
			this.label = label;
			this.extensions = extensions;
		}

		/** The machine a file name of {@code name} asks for, or null when it asks for nothing. */
		static Machine forName(String name) {
			int dot = name.lastIndexOf('.');
			if (dot < 0) {
				return null;
			}
			String extension = name.substring(dot + 1).toLowerCase();
			for (Machine machine : values()) {
				for (String candidate : machine.extensions) {
					if (candidate.equals(extension)) {
						return machine;
					}
				}
			}
			return null;
		}
	}

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
		// A name that says sg or sc is not argued about, but when two of this extension's loaders do
		// reach for one image the 8 bit console with a header of its own has to win.
		return 2;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		if (Machine.forName(provider.getName()) == null) {
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
		new SgMemoryMap(program, settings).build();
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
		return options;
	}

	/** The 64 KiB view one of these cartridges gets. Exists per load, as every map does. */
	private static class SgMemoryMap {

		private final Program program;
		private final MessageLog log;
		private final TaskMonitor monitor;

		private final FlatProgramAPI fpa;
		private final Memory memory;
		private final AddressSpace ram;
		private final AddressSpace io;

		private final FileBytes romBytes;
		private final long romLength;

		private final Machine machine;
		private final boolean hardwarePorts;
		private final boolean verify;

		SgMemoryMap(Program program, ImporterSettings settings)
				throws IOException, CancelledException {

			this.program = program;
			this.log = settings.log();
			this.monitor = settings.monitor();
			this.fpa = new FlatProgramAPI(program, monitor);
			this.memory = program.getMemory();
			this.ram = program.getAddressFactory().getDefaultAddressSpace();
			this.io = program.getAddressFactory().getAddressSpace("io");
			this.romBytes = MemoryBlockUtils.createFileBytes(program, settings.provider(), monitor);
			this.romLength = settings.provider().length();
			this.machine = Machine.forName(settings.provider().getName());

			List<Option> options = settings.options();
			this.hardwarePorts =
				SegaLoadOptions.getBoolean(options, SegaLoadOptions.NAME_HW_REGISTERS, true);
			this.verify = SegaLoadOptions.getBoolean(options, SegaLoadOptions.NAME_VERIFY, true);
		}

		void build() throws IOException, CancelledException {
			monitor.setMessage(String.format("%s : Start loading", LOADER_NAME));

			log.appendMsg(UNTESTED);
			log.appendMsg(String.format("%s: a %d KiB image placed as the machine sees it at power "
				+ "on", machine.label, romLength / 1024));

			boolean paged = romLength > CART_WINDOW;
			createRom(paged);
			createRam(paged);
			if (hardwarePorts) {
				if (machine == Machine.SG_1000) {
					createSgPorts();
				}
				else {
					createScPorts();
				}
			}
			markEntryPoint();

			if (verify) {
				log.appendMsg(
					"neither computer puts a header in front of a cartridge the way the Master System "
						+ "does, so the region and checksum checks of the other 8 bit loader have "
						+ "nothing to work on here");
			}

			monitor.setMessage(String.format("%s : Loading done", LOADER_NAME));
		}

		/**
		 * Power on leaves the cartridge mirrored over 0x0000-0xBFFF with the mask of the nearest
		 * power of two above its size. An image bigger than the window cannot be mirrored that way,
		 * and what the console would have to do instead has no answer in either computer.
		 */
		private void createRom(boolean paged) throws IOException {
			if (paged) {
				createPagedRom();
				return;
			}

			long span = Math.max(nearestPow2(romLength), 0x1000L);
			fileBlock("ROM", 0L, 0L, Math.min(CART_WINDOW, span), true, false, true, false,
				"the cartridge, mirrored over the window by the mask of its own size; map taken "
					+ "from the emulator's sources, not from a cartridge");

			int echoes = 0;
			for (long at = span; at < CART_WINDOW && echoes < MAX_ECHOES; at += span) {
				mirrorBlock(echoes == 0 ? "ROM_ECHO" : "ROM_ECHO_" + echoes, 0L, at,
					Math.min(span, CART_WINDOW - at));
				echoes++;
			}
			if (echoes > 0) {
				log.appendMsg(String.format(
					"%d mirror(s) of the cartridge placed above it, because %d byte(s) of image leave "
						+ "the mask short of the 0x%X byte window the console decodes",
					echoes, romLength, CART_WINDOW));
			}
			if (echoes == MAX_ECHOES && span < CART_WINDOW) {
				log.appendMsg(String.format(
					"the mask keeps mirroring past 0x%X; stopped there, the rest would only repeat what is shown",
					MAX_ECHOES * span));
			}
		}

		/**
		 * An image too big for the window is paged by the scheme of the Master System, which neither
		 * of these computers has. This is what an emulator does to it, not what the hardware did.
		 */
		private void createPagedRom() throws IOException {
			fileBlock("ROM", 0L, 0L, PAGED_FIRST, true, false, true, false,
				"the first page, which stays put; map taken from the emulator's sources, not from a "
					+ "cartridge");

			fileBlock("ROM_BANK1", PAGED_FIRST, PAGED_FIRST, PAGED_SECOND - PAGED_FIRST, true,
				false, true, false, "page window moved by the register at 0xFFFC");
			fileBlock("ROM_BANK2", PAGED_SECOND, PAGED_SECOND, PAGED_THIRD - PAGED_SECOND, true,
				false, true, false, "page window moved by the register at 0xFFFD");
			fileBlock("ROM_BANK3", PAGED_THIRD, PAGED_THIRD, CART_WINDOW - PAGED_THIRD, true, false,
				true, false, "page window moved by the register at 0xFFFE");

			int banks = 0;
			for (long fileOffset = CART_WINDOW; fileOffset < romLength; fileOffset += 0x4000L) {
				long size = Math.min(0x4000L, romLength - fileOffset);
				fileBlock("ROM_BANK" + (4 + banks), PAGED_THIRD, fileOffset, size, true, false,
					true, true, String.format("file offset 0x%X, paged in by a write to 0xFFFE",
						fileOffset));
				banks++;
			}

			MemoryBlock mapper = MemoryBlockUtils.createUninitializedBlock(program, false,
				"MAPPER", toAddr(ram, MAPPER_REGISTERS), 4,
				"bank number of the three page windows, written as bytes", LOADER_NAME, true, true,
				false, log);
			if (mapper != null) {
				mapper.setVolatile(true);
			}
			createNamedByte(MAPPER_REGISTERS, "MAPPER_PAGE1");
			createNamedByte(MAPPER_REGISTERS + 1, "MAPPER_PAGE2");
			createNamedByte(MAPPER_REGISTERS + 2, "MAPPER_PAGE3");

			log.appendMsg(String.format(
				"BlastEm pages an image of %d byte(s) with the Master System mapper; an SG-1000 has no "
					+ "such thing, so this is what the emulator would do, not what the hardware did. %d "
					+ "further page(s) are overlays of 0x%X-0x%X.",
				romLength, banks, PAGED_THIRD, CART_WINDOW - 1));
		}

		/**
		 * The 8 KiB of the machine, which the console echoes over its own top 16 KiB. A paged image
		 * has that echo stop short of 0xFFFC, where its paging registers live.
		 */
		private void createRam(boolean paged) throws IOException {
			long echoSize = paged ? MAPPER_REGISTERS - RAM_ECHO_START : SYSTEM_RAM_SIZE;
			MemoryBlock work = MemoryBlockUtils.createUninitializedBlock(program, false, "RAM",
				toAddr(ram, SYSTEM_RAM_START), SYSTEM_RAM_SIZE,
				"the 8 KiB of the machine, echoed by the console over its own top 16 KiB",
				LOADER_NAME, true, true, false, log);
			if (work != null) {
				work.setVolatile(true);
			}

			mirrorBlock("RAM_ECHO", SYSTEM_RAM_START, RAM_ECHO_START, echoSize);
			if (paged) {
				log.appendMsg(String.format(
					"the echo of the system RAM stops at 0x%X because the paging registers of the scheme "
						+ "the image was pushed into live at 0x%X",
					MAPPER_REGISTERS - 1, MAPPER_REGISTERS));
			}
		}

		/**
		 * Ports of an SG-1000. The console decodes the video chip and the raster counter by the
		 * parity of the address, so the names below mark the pair every program of the time uses and
		 * the comment of each block says what the other addresses of the range answer.
		 */
		private void createSgPorts() {
			portBlock("CONTROLLER", 0x00, 0x40,
				"an odd address writes both controller ports, and the edge on the TH line latches "
					+ "the raster counter; the even address would be the memory control of an "
					+ "add-on, which nothing here decodes");

			portBlock("PSG", 0x40, 0x40,
				"any address of the range writes the tone generator; a read gives the raster "
					+ "counter, its high byte on an even address and its low byte on an odd one");
			portRegister(0x40, "HV_COUNTER_H");
			portRegister(0x41, "HV_COUNTER_L");

			portBlock("VDP", 0x80, 0x40,
				"even address is the data port of the video chip, odd address is its control and "
					+ "status");
			portRegister(0x80, "VDP_DATA");
			portRegister(0x81, "VDP_CTRL");

			portBlock("CONTROLLER_DATA", 0xC0, 0x40,
				"reads answer 0xFF everywhere but on the four addresses named below");
			portRegister(0xDC, "IO_DATA_AB");
			portRegister(0xDD, "IO_CTRL");
			portRegister(0xC0, "IO_DATA_AB_ALT");
			portRegister(0xC1, "IO_CTRL_ALT");
		}

		/**
		 * Ports of an SC-3000, whose cartridge slot carries an 8255 next to the video chip. The
		 * emulator gives each of those chips a range of 32 addresses and picks the register from the
		 * two low bits, so no single address can be named as the only one that reaches it; the video
		 * pair at 0xA0 is the exception, because that range holds nothing else.
		 */
		private void createScPorts() {
			portBlock("PPI_VDP", 0x00, 0x20,
				"the 8255 read with the data port of the video chip wired into it; every write is "
					+ "taken and nothing decodes it");
			portBlock("VDP_PSG", 0x20, 0x20,
				"the video chip by the parity of the address, and a write reaches the tone "
					+ "generator with it");
			portBlock("PPI_PSG", 0x40, 0x20,
				"the 8255 by its two low bits, and a write reaches the tone generator with it");
			portBlock("PSG", 0x60, 0x20,
				"any address of the range writes the tone generator, and nothing is read here");
			portBlock("PPI_VDP2", 0x80, 0x20,
				"the 8255 read with the data port of the video chip wired into it, and written "
					+ "through both");

			portBlock("VDP", 0xA0, 0x20,
				"even address is the data port of the video chip, odd address is its control and "
					+ "status");
			portRegister(0xA0, "VDP_DATA");
			portRegister(0xA1, "VDP_CTRL");

			portBlock("PPI", 0xD0, 0x30,
				"the 8255 by its two low bits: port A, port B, port C and its control register, in "
					+ "that order and again every four addresses");
		}

		/**
		 * The reset of these machines is the cartridge itself: the Z80 starts at 0 with interrupts
		 * held off, and the restart points and the restart of the non maskable interrupt are the
		 * addresses every program of the time puts its handlers at.
		 */
		private void markEntryPoint() {
			Address reset = toAddr(ram, 0L);
			Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
			AddressSetView disassembled = dis.disassemble(reset, null, false);
			AutoAnalysisManager.getAnalysisManager(program).codeDefined(disassembled);
			if (disassembled.isEmpty()) {
				// An image that starts with nothing the language knows still has to be seeded.
				AutoAnalysisManager.getAnalysisManager(program).codeDefined(new AddressSet(reset));
			}

			fpa.createFunction(toAddr(ram, NMI_VECTOR), "NMI_ISR");
			for (long vector = RST_FIRST; vector <= RST_LAST; vector += 8) {
				fpa.createFunction(toAddr(ram, vector), String.format("RST_%02X", vector));
			}
		}

		/** The mask of the nearest power of two at or above a size, as the console makes its window. */
		private static long nearestPow2(long size) {
			long pow2 = 1;
			while (pow2 < size) {
				pow2 <<= 1;
			}
			return pow2;
		}

		/** Block backed by the image, clipped to what the window and the file allow. */
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
				MemoryBlock block = memory.createByteMappedBlock(name, toAddr(ram, mappedAddress),
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

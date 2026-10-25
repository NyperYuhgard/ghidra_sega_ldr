package sega.live;

import java.util.ArrayList;
import java.util.List;

import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Puts the bytes a machine is standing on into the program, so the listing can read what the trace
 * already said was run.
 * <p>
 * A dump answers a question the image cannot: what the program of a cartridge, or the boot stage of
 * a disc, left in work RAM. It is therefore written only where the program holds nothing. A block
 * that came from a file keeps its own bytes: the image says what has to be there, a dump only says
 * what happened to be.
 */
public class MemoryFiller {

	/** One run of bytes, counted in the program's own address space. */
	public record Range(long address, byte[] bytes) {
	}

	/** What a fill did, in the words the panel repeats. */
	public static class Stats {

		public int wholeBlocks;
		public int splitBlocks;
		public int leftAlone;
		public long bytes;
		public final List<String> notes = new ArrayList<>();

		@Override
		public String toString() {
			return String.format("%d block(s) filled whole, %d cut around the dump, %,d byte(s), "
				+ "%d left alone", wholeBlocks, splitBlocks, bytes, leftAlone);
		}
	}

	private final Program program;
	private final Memory memory;
	private final AddressSpace space;
	private final TaskMonitor monitor;
	private final Stats stats = new Stats();

	private MemoryFiller(Program program, TaskMonitor monitor) {
		this.program = program;
		this.memory = program.getMemory();
		this.space = program.getAddressFactory().getDefaultAddressSpace();
		this.monitor = monitor;
	}

	public static Stats fill(Program program, List<Range> ranges, TaskMonitor monitor)
			throws CancelledException {

		MemoryFiller filler = new MemoryFiller(program, monitor);
		filler.work(ranges, monitor);
		return filler.stats;
	}

	private void work(List<Range> ranges, TaskMonitor monitor) throws CancelledException {
		monitor.initialize(ranges.size());
		monitor.setMessage("Filling the memory the machine was running on");

		int index = 0;
		for (Range range : ranges) {
			monitor.checkCancelled();
			monitor.setProgress(index++);
			if (range.bytes().length == 0) {
				continue;
			}
			Address start = space.getAddress(range.address());
			Address end = space.getAddress(range.address() + range.bytes().length - 1);

			for (MemoryBlock block : memory.getBlocks()) {
				// An alias shares the bytes of what it mirrors, and an overlay belongs to a window
				// somebody else already holds: both are filled by the block they sit on.
				if (block.isMapped() || block.isOverlay()
						|| !block.getStart().getAddressSpace().equals(space)) {
					continue;
				}
				long from = Math.max(start.getOffset(), block.getStart().getOffset());
				long to = Math.min(end.getOffset(), block.getEnd().getOffset());
				if (from <= to) {
					apply(block, range, space.getAddress(from), space.getAddress(to));
				}
			}
		}
	}

	private void apply(MemoryBlock block, Range range, Address from, Address to) {
		if (block.isInitialized()) {
			stats.leftAlone++;
			stats.notes.add(block.getName() + " already holds bytes of its own");
			return;
		}

		// How far into the dump the window begins: a dump can be wider than the block it lands on.
		long into = offset(from) - range.address();
		long covered = offset(to) - offset(from) + 1;
		if (covered == block.getSize()) {
			fillWhole(block, range, into);
			return;
		}
		cutAround(block, range, from, to, covered, into);
	}

	/** The common case: the dump is exactly the window, so the window only has to gain its bytes. */
	private void fillWhole(MemoryBlock block, Range range, long skip) {
		try {
			MemoryBlock filled = memory.convertToInitialized(block, (byte) 0);
			memory.setBytes(filled.getStart(), range.bytes(), (int) skip, (int) filled.getSize());
			stats.wholeBlocks++;
			stats.bytes += filled.getSize();
		}
		catch (LockException | MemoryAccessException e) {
			stats.leftAlone++;
			stats.notes.add(block.getName() + ": " + e.getMessage());
		}
	}

	/**
	 * The dump covers part of a window. Ghidra will not put two blocks over one range, so the window
	 * is taken apart and put back as the runs the dump leaves it with: the name of the original goes
	 * to the first run and the rest count up, which is how a window cut by what a disc places is
	 * already named in this extension.
	 */
	private void cutAround(MemoryBlock block, Range range, Address from, Address to, long covered,
			long into) {

		String name = block.getName();
		List<Symbol> labels = labelsInside(block);
		String comment = block.getComment();
		boolean read = block.isRead();
		boolean write = block.isWrite();
		boolean execute = block.isExecute();
		boolean volatileBlock = block.isVolatile();
		long before = offset(from) - offset(block.getStart());
		long after = block.getSize() - before - covered;

		try {
			memory.removeBlock(block, monitor);
		}
		catch (LockException e) {
			stats.leftAlone++;
			stats.notes.add(name + ": " + e.getMessage());
			return;
		}

		int runs = 0;
		try {
			if (before > 0) {
				runs = emptyRun(pick(name, runs), offset(block.getStart()), before, comment, read,
					write, execute, volatileBlock, runs);
			}
			MemoryBlock filled =
				memory.createInitializedBlock(pick(name, runs), from, covered, (byte) 0, monitor,
					false);
			describe(filled, comment, read, write, execute, volatileBlock);
			memory.setBytes(from, range.bytes(), (int) into, (int) covered);
			runs++;
			if (after > 0) {
				runs = emptyRun(pick(name, runs), offset(to) + 1, after, comment, read, write, execute,
					volatileBlock, runs);
			}
		}
		catch (LockException | MemoryConflictException | AddressOverflowException
				| CancelledException | IllegalArgumentException | MemoryAccessException e) {
			stats.notes.add(String.format(
				"%s was taken apart to hold the dump and could not be put back whole: %s", name,
				e.getMessage()));
			return;
		}

		relabel(labels);
		stats.splitBlocks++;
		stats.bytes += covered;
	}

	private int emptyRun(String name, long address, long size, String comment, boolean read,
			boolean write, boolean execute, boolean volatileBlock, int runs)

			throws LockException, MemoryConflictException, AddressOverflowException,
			CancelledException {

		MemoryBlock block =
			memory.createUninitializedBlock(name, space.getAddress(address), size, false);
		describe(block, comment, read, write, execute, volatileBlock);
		return runs + 1;
	}

	/**
	 * The name of the next run of a window that has to be cut. The window keeps its own name and the
	 * runs after it count from two, which is how a disc places what it loads into a window that the
	 * loader already made.
	 */
	private static String pick(String name, int runs) {
		return runs == 0 ? name : name + "_" + (runs + 1);
	}

	private void describe(MemoryBlock block, String comment, boolean read, boolean write,
			boolean execute, boolean volatileBlock) {

		block.setRead(read);
		block.setWrite(write);
		block.setExecute(execute);
		block.setVolatile(volatileBlock);
		if (comment != null) {
			block.setComment(comment);
		}
	}

	/** The names a block carries, kept across the surgery that has to remove them with the block. */
	private List<Symbol> labelsInside(MemoryBlock block) {
		List<Symbol> labels = new ArrayList<>();
		SymbolIterator symbols = program.getSymbolTable()
				.getSymbols(new AddressSet(block.getStart(), block.getEnd()), SymbolType.LABEL,
					false);
		while (symbols.hasNext()) {
			labels.add(symbols.next());
		}
		return labels;
	}

	private void relabel(List<Symbol> labels) {
		for (Symbol label : labels) {
			try {
				program.getSymbolTable().createLabel(label.getAddress(), label.getName(),
					SourceType.IMPORTED);
			}
			catch (InvalidInputException e) {
				stats.notes.add(label.getName() + ": " + e.getMessage());
			}
		}
	}

	private long offset(Address address) {
		return address.getOffset();
	}
}

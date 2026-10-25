package sega.live;

import java.util.List;

import ghidra.framework.cmd.BackgroundCommand;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Writes a memory dump that has already been read into the program, in one transaction of its own.
 * <p>
 * The reading belongs to whoever holds the emulator: this command only ever takes bytes it is
 * handed, so the same command serves the debugger of the emulator and its remote stub, and a script
 * can fill from a file the same way.
 */
public class RamDumpCommand extends BackgroundCommand<Program> {

	public static final String NAME = "Fill RAM from BlastEm";

	private final List<MemoryFiller.Range> ranges;
	private final MemoryFiller.Stats stats = new MemoryFiller.Stats();
	private final Runnable onFinish;

	public RamDumpCommand(List<MemoryFiller.Range> ranges, Runnable onFinish) {
		super(NAME, true, true, false);
		this.ranges = ranges;
		this.onFinish = onFinish;
	}

	@Override
	public boolean applyTo(Program program, TaskMonitor monitor) {
		try {
			MemoryFiller.Stats done = MemoryFiller.fill(program, ranges, monitor);
			stats.wholeBlocks = done.wholeBlocks;
			stats.splitBlocks = done.splitBlocks;
			stats.leftAlone = done.leftAlone;
			stats.bytes = done.bytes;
			stats.notes.addAll(done.notes);
			return true;
		}
		catch (CancelledException e) {
			return false;
		}
		finally {
			if (onFinish != null) {
				onFinish.run();
			}
		}
	}

	public MemoryFiller.Stats getStats() {
		return stats;
	}
}

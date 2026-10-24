package sega.live;

import java.util.Collection;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Turns the addresses BlastEm logged into code and functions.
 * <p>
 * The emulator reports the first byte of every block it translates, which is exactly the unit the
 * disassembler works in: one logged address is one entry point or one branch target, never a stray
 * byte in the middle of an instruction.
 */
public class IngestCommand extends BackgroundCommand<Program> {

	public static final String NAME = "Ingest BlastEm trace";

	/**
	 * How the logged addresses are turned into code, which is the one thing the user can really
	 * trade: promptness of the listing against completeness of what the analyzers leave behind.
	 */
	public enum Mode {

		/** Hand every batch to the analysis manager; the listing fills when the tool is idle. */
		ANALYSIS_QUEUE,

		/** Disassemble inside the batch's own transaction, and re-analyze the new code in one go. */
		DIRECT,

		/** Disassemble inside the batch's own transaction and ask for no analysis at all. */
		DISASSEMBLE_ONLY;
	}

	/** What a batch was made of, so the panel can show honest numbers instead of guesses. */
	public static class Stats {

		/** Addresses the emulator logged that fall on runnable memory of this program. */
		public int runnable;

		/** Of those, the ones that had no instruction yet. */
		public int newCode;

		/** New code that no existing function reaches, so a function is asked for there. */
		public int newFunctions;

		/** Functions the program really gained, once known: -1 while the analyzer is still busy. */
		public int createdFunctions = -1;

		/** Runnable addresses already disassembled; nothing to do for them. */
		public int alreadyCode;

		/** Addresses outside every block, or in memory the filter leaves out. */
		public int skipped;

		/** Addresses the machine did run at, in a block that holds no bytes for Ghidra to read. */
		public int noBytes;

		public long lastAddress;

		/** Takes every count from the plan that has just been worked through. */
		void accept(Stats source) {
			runnable = source.runnable;
			newCode = source.newCode;
			newFunctions = source.newFunctions;
			createdFunctions = source.createdFunctions;
			alreadyCode = source.alreadyCode;
			skipped = source.skipped;
			noBytes = source.noBytes;
			lastAddress = source.lastAddress;
		}

		@Override
		public String toString() {
			String functions = createdFunctions >= 0
				? String.format("%d functions created", createdFunctions)
				: String.format("functions asked for %d", newFunctions);
			String text = String.format("%d reached, %d new code, %s, %d already known, %d outside the map",
				runnable, newCode, functions, alreadyCode, skipped);
			if (noBytes > 0) {
				text += String.format(", %d with no bytes loaded yet", noBytes);
			}
			return text;
		}
	}

	/** The work a batch asks for, split from the way it gets applied. */
	public static class Plan {

		public final AddressSet disassemble = new AddressSet();
		public final AddressSet functionEntries = new AddressSet();
		public final Stats stats = new Stats();
	}

	private final Collection<Long> addresses;
	private final boolean includeRam;
	private final Mode mode;
	private final Stats stats = new Stats();
	private final Runnable onFinish;

	/** The plan that was worked out; null until the command has run. */
	private Plan plan;

	public IngestCommand(Collection<Long> addresses, boolean includeRam, Mode mode,
			Runnable onFinish) {
		super(NAME, true, true, false);
		this.addresses = addresses;
		this.includeRam = includeRam;
		this.mode = mode;
		this.onFinish = onFinish;
	}

	@Override
	public boolean applyTo(Program program, TaskMonitor monitor) {
		try {
			Plan applied = plan(program, addresses, includeRam, monitor);
			plan = applied;
			boolean result = mode == Mode.ANALYSIS_QUEUE
				? applyViaAnalysisManager(program, applied, monitor)
				: applyNow(program, applied, monitor);
			// Accepted last: applying the plan can still change what it asked for.
			stats.accept(applied.stats);
			return result;
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

	/**
	 * The addresses that were asked to become code, so a caller running the quick modes can have
	 * the analyzers look at them later, in one pass, instead of batch by batch.
	 */
	public AddressSetView getDisassembled() {
		return plan == null ? new AddressSet() : plan.disassemble;
	}

	/**
	 * Decides which of the logged addresses are worth looking at.
	 * <p>
	 * Work RAM, the battery backed RAM and the register windows are left out unless asked for: on
	 * this hardware code does not run from them, so the addresses the machine puts there are
	 * usually data that the 68000 happened to fetch because a loop counter ran off. Those blocks
	 * come uninitialized from the loader, which is the other half of the same test.
	 */
	public static Plan plan(Program program, Collection<Long> addresses, boolean includeRam,
			TaskMonitor monitor) {

		Plan plan = new Plan();
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Memory memory = program.getMemory();
		Listing listing = program.getListing();
		FunctionManager functions = program.getFunctionManager();
		long spaceMax = space.getMaxAddress().getOffset();

		monitor.initialize(addresses.size());
		monitor.setMessage("Reading the trace");

		int index = 0;
		for (long value : addresses) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.setProgress(index++);

			if (value > spaceMax) {
				plan.stats.skipped++;
				continue;
			}
			Address address = space.getAddress(value);
			MemoryBlock block = memory.getBlock(address);
			if (block == null || !block.isExecute()) {
				plan.stats.skipped++;
				continue;
			}
			boolean scratch = block.isVolatile() || !block.isInitialized();
			if (scratch && !includeRam) {
				plan.stats.skipped++;
				continue;
			}

			plan.stats.runnable++;
			plan.stats.lastAddress = value;

			if (!block.isInitialized()) {
				// RAM was asked for, but Ghidra cannot read an instruction out of a block that
				// holds no bytes: the memory the emulator is using has to be dumped in first.
				plan.stats.noBytes++;
				continue;
			}

			if (listing.getInstructionAt(address) != null) {
				plan.stats.alreadyCode++;
				continue;
			}
			plan.disassemble.add(address);
			plan.stats.newCode++;
			if (functions.getFunctionContaining(address) == null) {
				plan.functionEntries.add(address);
				plan.stats.newFunctions++;
			}
		}

		return plan;
	}

	/**
	 * Hands the plan to the analysis manager, which runs it when the tool is idle and lets the
	 * analyzers follow the code it disassembles.
	 * <p>
	 * A headless run has no tool waiting for that queue, so the work is done in the caller's
	 * transaction instead when the manager reports that nothing will pick it up.
	 */
	public static boolean applyViaAnalysisManager(Program program, Plan plan, TaskMonitor monitor)
			throws CancelledException {
		if (plan.disassemble.isEmpty()) {
			return true;
		}
		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(program);
		manager.disassemble(plan.disassemble);
		if (!plan.functionEntries.isEmpty()) {
			manager.createFunction(plan.functionEntries, true);
		}
		if (manager.startBackgroundAnalysis()) {
			return true;
		}
		return applyNow(program, plan, monitor);
	}

	/**
	 * Tells the analyzers to look again at addresses that were made code outside their queue, and
	 * starts the background pass that will do it.
	 */
	public static void analyzeAfterwards(Program program, AddressSetView addresses) {
		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(program);
		manager.reAnalyzeAll(addresses);
		manager.startBackgroundAnalysis();
	}

	/**
	 * Does the work in the caller's transaction instead of queueing it, for the cases where no
	 * analysis tool is around to run a queue: a script that ingests a saved log.
	 */
	public static boolean applyNow(Program program, Plan plan, TaskMonitor monitor)
			throws CancelledException {
		if (plan.disassemble.isEmpty()) {
			return true;
		}
		DisassembleCommand disassemble = new DisassembleCommand(plan.disassemble, null, true);
		if (!disassemble.applyTo(program, monitor)) {
			monitor.checkCancelled();
			return false;
		}

		// The disassembly is done, so a block that fell into a function the listing knows now is
		// not left to start one of its own.
		FunctionManager functions = program.getFunctionManager();
		AddressSet entries = new AddressSet();
		int entryCount = 0;
		for (Address address : plan.functionEntries.getAddresses(true)) {
			if (functions.getFunctionContaining(address) == null) {
				entries.add(address);
				entryCount++;
			}
		}
		plan.stats.newFunctions = entryCount;

		if (!entries.isEmpty()) {
			int before = functions.getFunctionCount();
			CreateFunctionCmd create = new CreateFunctionCmd(entries, true);
			if (!create.applyTo(program, monitor)) {
				monitor.checkCancelled();
				return false;
			}
			// Several logged blocks sit inside one function, so the entries are not the number of
			// functions the program ended up with.
			plan.stats.createdFunctions = functions.getFunctionCount() - before;
		}
		return true;
	}

	public Stats getStats() {
		return stats;
	}
}

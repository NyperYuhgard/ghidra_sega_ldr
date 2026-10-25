package sega.live;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.SwingUtilities;
import javax.swing.Timer;

import docking.ComponentProvider;
import ghidra.app.DeveloperPluginPackage;
import ghidra.app.nav.Navigatable;
import ghidra.app.nav.NavigatableRegistry;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;

/**
 * Keeps the listing in step with the emulator: everything the game really runs ends up
 * disassembled, without waiting for a static pass to guess that the code is there.
 * <p>
 * BlastEm is started with {@code -l}, which logs the first address of every 68000 block it
 * translates. Those addresses are read as they are written and handed to the analyzer in batches,
 * one transaction per batch, so the window stays responsive while the game plays.
 */
@PluginInfo(status = PluginStatus.RELEASED, packageName = DeveloperPluginPackage.NAME,
	category = PluginCategoryNames.DEBUGGER, shortDescription = "BlastEm live disassembly",
	description = "Runs BlastEm with its address log turned on and disassembles, in the program that is "
		+ "open, every 68000 block the game reaches while it plays. A log saved by an earlier run can be "
		+ "ingested the same way.")
public class BlastEmLivePlugin extends ProgramPlugin implements BlastEmLiveProvider.Controls {

	/** How often the queue is looked at: short enough to feel live, long enough to batch. */
	private static final int FLUSH_MILLIS = 120;

	/** Ceiling for one transaction, so a busy frame cannot freeze the listing. */
	private static final int MAX_BATCH = 256;

	/** The most one window is asked for whole: bigger ones give the span the trace reached. */
	private static final int MAX_DUMP = 0x10000;

	/** How long a debugger is given to write the file it was asked for. */
	private static final long DUMP_WAIT_MILLIS = 5000;

	private BlastEmLiveProvider provider;
	private Timer flushTimer;

	private final AddressFeed feed = new AddressFeed();

	private BlastEmRunner runner;
	private BlastEmTraceReader reader;
	private RspChannel remote;

	/** True while a batch is being applied; only one write at a time is worth queuing. */
	private final AtomicBoolean ingesting = new AtomicBoolean();

	/** The program the emulator was started for: its addresses mean nothing to any other. */
	private Program session;

	/** Chosen when the session starts, so the whole run applies one answer consistently. */
	private IngestCommand.Mode sessionMode = IngestCommand.Mode.ANALYSIS_QUEUE;

	/** Also chosen when the session starts: a dump is asked for the way the session was opened. */
	private BlastEmRunner.DebugChannel sessionChannel = BlastEmRunner.DebugChannel.NONE;

	/** Every address this session ran, including the ones in RAM that had nothing to read. */
	private final AddressSet sessionHits = new AddressSet();

	/** Code made outside the analyzer's queue, kept for the single analysis pass done at Stop. */
	private final AddressSet pendingAnalysis = new AddressSet();
	private int pendingAddresses;

	public BlastEmLivePlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		provider = new BlastEmLiveProvider(tool, this);
		tool.addComponentProvider(provider, false);

		flushTimer = new Timer(FLUSH_MILLIS, event -> flush());
		flushTimer.setCoalesce(true);
		flushTimer.start();
	}

	@Override
	protected void programActivated(Program program) {
		provider.setProgram(program);
		feed.forget();
		sessionHits.clear();
	}

	@Override
	protected void programClosed(Program program) {
		if (program == session) {
			provider.log("The program the emulator was started for closed; the session is over.");
			stopSession(false);
		}
	}

	@Override
	public void start(BlastEmLiveProvider settings) {
		if (currentProgram == null) {
			provider.log("Open the ROM's program first: the logged addresses have to land somewhere.");
			return;
		}
		if (runner != null) {
			return;
		}

		String rom = settings.getRomPath();
		if (rom.isEmpty() || !new File(rom).isFile()) {
			provider.log("Point the ROM field at the image BlastEm should run.");
			return;
		}
		String refusal = DiscSheet.refusalFor(rom);
		if (refusal != null) {
			provider.log(refusal);
			return;
		}

		try {
			runner = new BlastEmRunner(settings.getWorkingDirectory());
		}
		catch (Exception e) {
			provider.log("That trace folder is not usable: " + e.getMessage());
			runner = null;
			return;
		}

		feed.forget();
		sessionHits.clear();
		session = currentProgram;
		sessionMode = settings.getMode();
		sessionChannel = settings.getMemoryChannel();
		pendingAnalysis.clear();
		String imported = currentProgram.getExecutablePath();
		if (imported != null && !DiscSheet.sameDisc(imported, rom)) {
			provider.log("Warning: this program came from " + imported + ", and BlastEm is being "
				+ "pointed at " + rom + ". Addresses from the second image will be applied to the first.");
		}
		provider.log("Trace folder: " + runner.getWorkingDirectory());
		provider.log("Disassembling in the \"" + BlastEmLiveProvider.modeLabel(sessionMode)
			+ "\" mode.");

		try {
			runner.start(settings.getExecutablePath(), settings.getMachine(), rom,
				settings.getExtraArguments(), sessionChannel, provider::log);
		}
		catch (Exception e) {
			provider.log("BlastEm did not start: " + e.getMessage());
			runner = null;
			return;
		}
		provider.log("Running: " + runner.getCommandLine());

		if (sessionChannel == BlastEmRunner.DebugChannel.REMOTE) {
			remote = new RspChannel(runner);
			provider.log("With the remote stub on, BlastEm keeps its text out of the pipe; it is "
				+ "written to " + runner.getErrorFile());
		}
		resumeEmulator();

		reader = new BlastEmTraceReader(runner.traceFile(DiscSheet.traceNameOf(session)), this::offer,
			provider::log);
		reader.startTail();
		provider.setRunning(true);
		provider.log("BlastEm is running; every block it translates becomes code.");
	}

	@Override
	public void stop() {
		stopSession(true);
	}

	/**
	 * Both debuggers take the machine over and leave it stopped at the reset vector, so a session
	 * with a channel only plays once this is said to it. Nothing is waited for: the emulator has no
	 * way to answer that it is listening, and one line more or less costs nothing.
	 */
	private void resumeEmulator() {
		if (sessionChannel == BlastEmRunner.DebugChannel.NONE) {
			return;
		}
		try {
			if (sessionChannel == BlastEmRunner.DebugChannel.NATIVE) {
				runner.writeLine("c");
			}
			else {
				remote.resume();
			}
			provider.log("The emulator was told to run; press Fill RAM… when the machine is stopped "
				+ "in its debugger again (the u key does that while the game plays).");
		}
		catch (Exception e) {
			provider.log("The emulator did not take the command to run: " + e.getMessage());
		}
	}

	@Override
	public void fillRam() {
		Program program = session;
		if (program == null || runner == null) {
			provider.log("Fill RAM… works on a running session: start one first.");
			return;
		}
		if (sessionChannel == BlastEmRunner.DebugChannel.NONE) {
			provider.log("No channel was chosen, so nothing can be asked of the emulator.");
			return;
		}
		if (ingesting.get()) {
			provider.log("Wait for the batch in progress to finish.");
			return;
		}

		List<MemoryFiller.Range> ranges;
		try {
			ranges = readDump(program);
		}
		catch (Exception e) {
			provider.log("Nothing came of the request: " + e.getMessage());
			return;
		}
		if (ranges.isEmpty()) {
			provider.log("The trace of this session never reached memory that holds no bytes, so "
				+ "there is nothing a dump could add.");
			return;
		}

		ingesting.set(true);
		final RamDumpCommand[] holder = new RamDumpCommand[1];
		holder[0] = new RamDumpCommand(ranges, () -> {
			RamDumpCommand command = holder[0];
			ingesting.set(false);
			SwingUtilities.invokeLater(() -> reportDump(command, ranges));
		});
		tool.executeBackgroundCommand(holder[0], program);
	}

	/**
	 * The windows the machine ran in, read out of the emulator. Only memory that carries nothing is
	 * asked for: the bytes of the image are already in the program and a dump could only corrupt
	 * them.
	 */
	private List<MemoryFiller.Range> readDump(Program program) throws IOException {
		List<MemoryFiller.Range> ranges = new ArrayList<>();
		Memory memory = program.getMemory();

		for (MemoryBlock block : memory.getBlocks()) {
			if (!block.isExecute() || block.isInitialized() || block.isMapped()
					|| block.isOverlay() || !block.getStart().getAddressSpace()
							.equals(program.getAddressFactory().getDefaultAddressSpace())) {
				continue;
			}
			long[] span = spanReached(block);
			if (span == null) {
				continue;
			}
			long start = span[0];
			long end = span[1];
			if (block.getSize() > MAX_DUMP) {
				provider.log(String.format("%s is %,d byte(s) and the trace reached it from 0x%X to "
					+ "0x%X: that is what is asked for, the rest of the window stays unknown.",
					block.getName(), block.getSize(), start, end));
			}
			else {
				start = block.getStart().getOffset();
				end = block.getEnd().getOffset();
			}
			int count = (int) (end - start + 1);
			ranges.add(new MemoryFiller.Range(start, readBytes(start, count)));
		}
		return ranges;
	}

	/** The first and last address of one block this session ran at, or null when it never did. */
	private long[] spanReached(MemoryBlock block) {
		AddressSetView reached;
		synchronized (sessionHits) {
			reached = sessionHits.intersectRange(block.getStart(), block.getEnd());
		}
		if (reached.isEmpty()) {
			return null;
		}
		return new long[] { reached.getMinAddress().getOffset(),
			reached.getMaxAddress().getOffset() };
	}

	private byte[] readBytes(long address, int count) throws IOException {
		if (sessionChannel == BlastEmRunner.DebugChannel.REMOTE) {
			return remote.readMemory(address, count);
		}
		return saveDump(address, count);
	}

	/**
	 * The emulator's own debugger writes the file it is asked to and gives nothing back over the
	 * pipe, so the answer is looked for in the folder it runs from, for as long as it could plausibly
	 * be taking.
	 */
	private byte[] saveDump(long address, int count) throws IOException {
		String name = "ghidra-dump-" + Long.toHexString(address) + ".bin";
		File dump = runner.workingFile(name);
		if (dump.isFile() && !dump.delete()) {
			throw new IOException(dump + " is left over from before and cannot be replaced");
		}
		runner.writeLine(String.format("save/b \"%s\" [0x%X] 0x%X", name, address, count));

		long deadline = System.currentTimeMillis() + DUMP_WAIT_MILLIS;
		long seen = -1;
		while (System.currentTimeMillis() < deadline) {
			if (dump.isFile()) {
				long size = dump.length();
				if (size == count && size == seen) {
					return Files.readAllBytes(dump.toPath());
				}
				seen = size;
			}
			try {
				Thread.sleep(50);
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				throw new IOException("the dump was given up on");
			}
		}
		throw new IOException(String.format(
			"%s never appeared: BlastEm is not stopped in its debugger, so the command to save the "
				+ "memory is only buffered. Press the u key in the emulator window and ask again.",
			name));
	}

	private void reportDump(RamDumpCommand command, List<MemoryFiller.Range> ranges) {
		MemoryFiller.Stats stats = command.getStats();
		provider.log(String.format("RAM filled: %s", stats));
		for (String note : stats.notes) {
			provider.log(note);
		}

		// The trace of those addresses counted as unreachable a moment ago; give it another look.
		List<Long> addresses = new ArrayList<>();
		for (MemoryFiller.Range range : ranges) {
			for (int i = 0; i < range.bytes().length; i += 2) {
				// The 68000 and the SH-2 both start a block at an even address, and a logged address
				// is one per instruction fetch: the odd half of a window never runs.
				addresses.add(range.address() + i);
			}
		}
		if (addresses.isEmpty()) {
			return;
		}
		IngestCommand.Plan plan =
			IngestCommand.plan(session, addresses, true, TaskMonitor.DUMMY);
		provider.log(String.format("of the %,d address(es) the dump covers, %d now have bytes to "
			+ "disassemble and %d were already known", addresses.size(), plan.stats.newCode,
			plan.stats.alreadyCode));
		if (plan.stats.newCode == 0) {
			return;
		}
		ingesting.set(true);
		final IngestCommand[] holder = new IngestCommand[1];
		holder[0] = new IngestCommand(addresses, true, sessionMode, () -> {
			IngestCommand ingest = holder[0];
			ingesting.set(false);
			SwingUtilities.invokeLater(() -> {
				provider.log("RAM filled: " + stats + "; the trace of those addresses is now "
					+ "disassembled (" + ingest.getStats() + ")");
				provider.setCounts(String.format("%,d seen · %s", feed.totalCount(),
					ingest.getStats()));
			});
		});
		tool.executeBackgroundCommand(holder[0], session);
	}

	@Override
	public void settingsChanged() {
		// Addresses refused under the old filter may be worth taking now.
		feed.forget();
	}

	@Override
	public void ingestFile(String path, BlastEmLiveProvider settings) {
		Program program = currentProgram;
		if (program == null) {
			provider.log("Open the ROM's program first.");
			return;
		}

		File log = new File(path);
		if (!log.isFile()) {
			provider.log("No such log: " + path);
			return;
		}
		if (ingesting.get()) {
			provider.log("Wait for the batch in progress to finish.");
			return;
		}

		ingesting.set(true);
		final IngestLogCommand[] holder = new IngestLogCommand[1];
		holder[0] = new IngestLogCommand(log, settings.isIncludingRam(), settings.getMode(), () -> {
			IngestLogCommand command = holder[0];
			ingesting.set(false);
			SwingUtilities.invokeLater(() -> reportLog(command));
		});
		tool.executeBackgroundCommand(holder[0], program);
	}

	private void reportLog(IngestLogCommand command) {
		provider.log(String.format("%,d addresses read from the log: %s",
			command.getLoggedAddresses(), command.getStats()));
		provider.setCounts(command.getStats().toString());

		List<String> problems = command.getProblems();
		for (int i = 0; i < Math.min(problems.size(), 10); i++) {
			provider.log(problems.get(i));
		}
		if (problems.size() > 10) {
			provider.log(String.format("... and %d more like those", problems.size() - 10));
		}
	}

	private void stopSession(boolean reanalyze) {
		if (reanalyze && sessionMode == IngestCommand.Mode.DIRECT
				&& !pendingAnalysis.isEmpty() && session != null) {
			provider.log(String.format("Letting the analyzers look at %,d new addresses.",
				pendingAddresses));
			IngestCommand.analyzeAfterwards(session, pendingAnalysis);
		}
		pendingAnalysis.clear();
		pendingAddresses = 0;

		if (reader != null) {
			reader.stop();
			reader = null;
		}
		if (remote != null) {
			remote.close();
			remote = null;
		}
		if (runner != null) {
			int code = runner.stop();
			provider.log(code < 0 ? "BlastEm did not answer; it may still be running."
					: "BlastEm exited with code " + code);
			runner = null;
		}
		session = null;
		sessionChannel = BlastEmRunner.DebugChannel.NONE;
		sessionHits.clear();
		provider.setRunning(false);
	}

	/** From the trace thread: queue what the emulator just reached. */
	private void offer(long address) {
		feed.offer(address);
		Program program = session;
		if (program != null && sessionChannel != BlastEmRunner.DebugChannel.NONE) {
			// A dump is asked for the windows this session ran in, and only this thread knows them.
			synchronized (sessionHits) {
				sessionHits.add(
					program.getAddressFactory().getDefaultAddressSpace().getAddress(address));
			}
		}
	}

	/** From the timer, on the Swing thread. */
	private void flush() {
		if (runner == null || session == null) {
			return;
		}
		if (!runner.isRunning()) {
			provider.log("BlastEm stopped on its own.");
			stopSession(true);
			return;
		}
		if (currentProgram != session) {
			provider.log("Another program took the focus, so the session stops: those addresses "
				+ "belong to the ROM that was open.");
			stopSession(true);
			return;
		}

		if (provider.isPaused()) {
			provider.setCounts(String.format("paused · %,d addresses seen", feed.totalCount()));
			return;
		}
		if (ingesting.get()) {
			return;
		}

		List<Long> batch = feed.drain(MAX_BATCH);
		if (batch.isEmpty()) {
			return;
		}

		ingesting.set(true);
		final IngestCommand[] holder = new IngestCommand[1];
		holder[0] = new IngestCommand(batch, provider.isIncludingRam(), sessionMode, () -> {
			IngestCommand command = holder[0];
			ingesting.set(false);
			SwingUtilities.invokeLater(() -> reportBatch(command));
		});
		tool.executeBackgroundCommand(holder[0], session);
	}

	private void reportBatch(IngestCommand command) {
		IngestCommand.Stats stats = command.getStats();
		provider.setCounts(String.format("%,d seen · %s", feed.totalCount(), stats));

		if (sessionMode == IngestCommand.Mode.DIRECT) {
			// Kept aside so the analyzers can be given all of it once, at Stop, instead of once
			// per batch while the game is running.
			pendingAnalysis.add(command.getDisassembled());
			pendingAddresses += stats.newCode;
		}

		if (provider.isFollowingPc() && stats.lastAddress != 0) {
			navigate(session, stats.lastAddress);
		}
	}

	private void navigate(Program program, long address) {
		if (program == null || program != currentProgram) {
			return;
		}
		Navigatable view = findView(program);
		if (view == null) {
			return;
		}
		Address at = program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
		view.goTo(program, new ProgramLocation(program, at));
	}

	private Navigatable findView(Program program) {
		ComponentProvider active = tool.getActiveComponentProvider();
		if (active instanceof Navigatable view && view.getProgram() == program) {
			return view;
		}
		for (Navigatable view : NavigatableRegistry.getRegisteredNavigatables(tool)) {
			if (view.getProgram() == program) {
				return view;
			}
		}
		return null;
	}

	@Override
	protected void dispose() {
		flushTimer.stop();
		if (reader != null) {
			reader.stop();
			reader = null;
		}
		if (remote != null) {
			remote.close();
			remote = null;
		}
		if (runner != null) {
			runner.stop();
			runner = null;
		}
		if (provider != null) {
			tool.removeComponentProvider(provider);
		}
		super.dispose();
	}
}

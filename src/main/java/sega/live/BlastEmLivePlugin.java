package sega.live;

import java.io.File;
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
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

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

	private BlastEmLiveProvider provider;
	private Timer flushTimer;

	private final AddressFeed feed = new AddressFeed();

	private BlastEmRunner runner;
	private BlastEmTraceReader reader;

	/** True while a batch is being applied; only one write at a time is worth queuing. */
	private final AtomicBoolean ingesting = new AtomicBoolean();

	/** The program the emulator was started for: its addresses mean nothing to any other. */
	private Program session;

	/** Chosen when the session starts, so the whole run applies one answer consistently. */
	private IngestCommand.Mode sessionMode = IngestCommand.Mode.ANALYSIS_QUEUE;

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

		try {
			runner = new BlastEmRunner(settings.getWorkingDirectory());
		}
		catch (Exception e) {
			provider.log("That trace folder is not usable: " + e.getMessage());
			runner = null;
			return;
		}

		feed.forget();
		session = currentProgram;
		sessionMode = settings.getMode();
		pendingAnalysis.clear();
		String imported = currentProgram.getExecutablePath();
		if (imported != null && !imported.equals(rom)) {
			provider.log("Warning: this program came from " + imported + ", and BlastEm is being "
				+ "pointed at " + rom + ". Addresses from the second image will be applied to the first.");
		}
		provider.log("Trace folder: " + runner.getWorkingDirectory());
		provider.log("Disassembling in the \"" + BlastEmLiveProvider.modeLabel(sessionMode)
			+ "\" mode.");

		try {
			runner.start(settings.getExecutablePath(), settings.getMachine(), rom,
				settings.getExtraArguments(), provider::log);
		}
		catch (Exception e) {
			provider.log("BlastEm did not start: " + e.getMessage());
			runner = null;
			return;
		}

		reader = new BlastEmTraceReader(runner.traceFile(), this::offer, provider::log);
		reader.startTail();
		provider.setRunning(true);
		provider.log("BlastEm is running; every block it translates becomes code.");
	}

	@Override
	public void stop() {
		stopSession(true);
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
		if (runner != null) {
			int code = runner.stop();
			provider.log(code < 0 ? "BlastEm did not answer; it may still be running."
					: "BlastEm exited with code " + code);
			runner = null;
		}
		session = null;
		provider.setRunning(false);
	}

	/** From the trace thread: queue what the emulator just reached. */
	private void offer(long address) {
		feed.offer(address);
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

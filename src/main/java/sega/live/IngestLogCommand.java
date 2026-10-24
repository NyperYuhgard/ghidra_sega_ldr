package sega.live;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import ghidra.framework.cmd.BackgroundCommand;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Reads a trace saved by an earlier run and disassembles all of it in one go.
 * <p>
 * Unlike the live session this waits for its own work: the log is finished, so the code it asks
 * for is there when the command returns, and the analyzers can be run over it right after.
 */
public class IngestLogCommand extends BackgroundCommand<Program> {

	private final File log;
	private final boolean includeRam;
	private final IngestCommand.Mode mode;
	private final IngestCommand.Stats stats = new IngestCommand.Stats();
	private final Runnable onFinish;

	private final List<Long> addresses = new ArrayList<>();
	private final List<String> problems = new ArrayList<>();

	public IngestLogCommand(File log, boolean includeRam, IngestCommand.Mode mode,
			Runnable onFinish) {
		super("Ingest BlastEm log", true, true, false);
		this.log = log;
		this.includeRam = includeRam;
		this.mode = mode;
		this.onFinish = onFinish;
	}

	@Override
	public boolean applyTo(Program program, TaskMonitor monitor) {
		try {
			BlastEmTraceReader reader =
				new BlastEmTraceReader(log, addresses::add, problems::add);
			reader.readAll();
			monitor.setMessage("Reading " + log.getName());

			IngestCommand.Plan plan =
				IngestCommand.plan(program, addresses, includeRam, monitor);
			boolean applied = mode == IngestCommand.Mode.ANALYSIS_QUEUE
				? IngestCommand.applyViaAnalysisManager(program, plan, monitor)
				: IngestCommand.applyNow(program, plan, monitor);
			stats.accept(plan.stats);

			if (mode == IngestCommand.Mode.DIRECT && !plan.disassemble.isEmpty()) {
				// The listing is right already, so the analyzers get all the new code at once
				// instead of once per batch.
				IngestCommand.analyzeAfterwards(program, plan.disassemble);
			}
			return applied;
		}
		catch (Exception e) {
			problems.add(e.getMessage());
			return false;
		}
		finally {
			if (onFinish != null) {
				onFinish.run();
			}
		}
	}

	public IngestCommand.Stats getStats() {
		return stats;
	}

	public int getLoggedAddresses() {
		return addresses.size();
	}

	public List<String> getProblems() {
		return problems;
	}
}

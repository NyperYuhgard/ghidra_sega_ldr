//Disassembles every 68000 block BlastEm logged while the ROM was running (-l writes address.log).
//@category Sega
//@keytool
//@menu
//@argument <log path> [ram] - the trace to read; add ram to take the addresses that land in work RAM too

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import sega.live.BlastEmTraceReader;
import sega.live.IngestCommand;

public class SegaIngestAddressLog extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String path = null;
		boolean includeRam = false;
		for (String argument : getScriptArgs()) {
			if (argument.equalsIgnoreCase("ram")) {
				includeRam = true;
			}
			else if (path == null) {
				path = argument;
			}
		}

		if (path == null) {
			path = askFile("Which trace should be read?", "Read").getAbsolutePath();
			includeRam = askYesNo("Which memory counts as code?",
				"Take the addresses that land in work RAM as code too?");
		}

		File log = new File(path);
		if (!log.isFile()) {
			println("No such log: " + path);
			return;
		}

		List<Long> addresses = new ArrayList<>();
		List<String> problems = new ArrayList<>();
		new BlastEmTraceReader(log, addresses::add, problems::add).readAll();
		if (addresses.isEmpty()) {
			println(log + " holds no addresses; BlastEm was run without -l, or it never got to "
				+ "translate anything.");
			return;
		}

		IngestCommand.Plan plan = IngestCommand.plan(currentProgram, addresses, includeRam, monitor);
		currentProgram.withTransaction("Ingest BlastEm trace",
			() -> IngestCommand.applyNow(currentProgram, plan, monitor));

		println(String.format("%,d addresses read: %s", addresses.size(), plan.stats));
		if (plan.stats.newFunctions > 0) {
			println("The blocks were disassembled and the ones nothing reaches got a function; "
				+ "run Analyze again to let the other analyzers follow the new code.");
		}
		for (int i = 0; i < Math.min(problems.size(), 10); i++) {
			println(problems.get(i));
		}
		if (problems.size() > 10) {
			println(String.format("... and %d more like those", problems.size() - 10));
		}
	}
}

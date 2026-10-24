package sega.live;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * The emulator process, and the directory its trace appears in.
 * <p>
 * BlastEm opens {@code address.log} in its working directory rather than on standard output, so
 * the directory is chosen before the process starts and the reader knows where to look.
 */
public class BlastEmRunner {

	private static final String TRACE_FILE = "address.log";
	private static final long STOP_MILLIS = 2000;

	private final Path workingDirectory;

	private Process process;

	public BlastEmRunner(String requestedDirectory) throws IOException {
		if (requestedDirectory == null || requestedDirectory.isBlank()) {
			workingDirectory = Files.createTempDirectory("ghidra-blastem-");
		}
		else {
			File directory = new File(requestedDirectory);
			if (!directory.isDirectory()) {
				throw new IOException(requestedDirectory + " is not a directory");
			}
			workingDirectory = directory.toPath();
		}
	}

	public File traceFile() {
		return workingDirectory.resolve(TRACE_FILE).toFile();
	}

	public Path getWorkingDirectory() {
		return workingDirectory;
	}

	/**
	 * Starts the emulator with the address log on.
	 *
	 * @param executable path to the blastem binary
	 * @param machine argument for {@code -m}, may be null to take the emulator's default
	 * @param rom the image to run
	 * @param extraArguments anything else the user types, split on spaces
	 * @param outputSink receives every line the emulator prints
	 */
	public void start(String executable, String machine, String rom, String extraArguments,
			Consumer<String> outputSink) throws IOException {

		List<String> command = new ArrayList<>();
		command.add(executable);
		if (machine != null && !machine.isBlank()) {
			command.add("-m");
			command.add(machine);
		}
		command.add("-l");
		for (String argument : split(extraArguments)) {
			command.add(argument);
		}
		command.add(rom);

		ProcessBuilder builder = new ProcessBuilder(command);
		builder.directory(workingDirectory.toFile());
		builder.redirectErrorStream(true);
		process = builder.start();
		process.getOutputStream().close();
		pumpOutput(outputSink);
	}

	/**
	 * Splits the extra arguments the way a shell would for the simple cases, keeping quoted runs
	 * together so a path with spaces survives.
	 */
	static List<String> split(String text) {
		List<String> parts = new ArrayList<>();
		if (text == null) {
			return parts;
		}
		StringBuilder current = new StringBuilder();
		char quote = 0;
		for (int i = 0; i < text.length(); i++) {
			char c = text.charAt(i);
			if (quote != 0) {
				if (c == quote) {
					quote = 0;
				}
				else {
					current.append(c);
				}
			}
			else if (c == '"' || c == '\'') {
				quote = c;
			}
			else if (Character.isWhitespace(c)) {
				if (current.length() > 0) {
					parts.add(current.toString());
					current.setLength(0);
				}
			}
			else {
				current.append(c);
			}
		}
		if (current.length() > 0) {
			parts.add(current.toString());
		}
		return parts;
	}

	private void pumpOutput(Consumer<String> sink) {
		// The process is captured: stop() clears the field while this thread is still reading.
		Process running = process;
		Thread pump = new Thread(() -> {
			try (BufferedReader reader = new BufferedReader(
				new InputStreamReader(running.getInputStream(), StandardCharsets.UTF_8))) {
				String line;
				while ((line = reader.readLine()) != null) {
					sink.accept(line);
				}
			}
			catch (IOException e) {
				if (running.isAlive()) {
					sink.accept("Lost the emulator's output: " + e.getMessage());
				}
			}
		}, "BlastEm output");
		pump.setDaemon(true);
		pump.start();
	}

	public boolean isRunning() {
		return process != null && process.isAlive();
	}

	/** @return the exit code, or -1 when the process is still up */
	public int stop() {
		if (process == null) {
			return 0;
		}
		Process running = process;
		process = null;
		running.destroy();
		try {
			if (!running.waitFor(STOP_MILLIS, java.util.concurrent.TimeUnit.MILLISECONDS)) {
				running.destroyForcibly();
				running.waitFor(STOP_MILLIS, java.util.concurrent.TimeUnit.MILLISECONDS);
			}
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			running.destroyForcibly();
		}
		return running.isAlive() ? -1 : running.exitValue();
	}

	/**
	 * Looks for the emulator the way a shell would, so an installed BlastEm needs no typing.
	 *
	 * @return the first executable named blastem on PATH, or null
	 */
	public static String findOnPath(String... names) {
		String path = System.getenv("PATH");
		if (path == null) {
			return null;
		}
		for (String directory : path.split(File.pathSeparator)) {
			for (String name : names) {
				File candidate = new File(directory, name);
				if (candidate.isFile() && candidate.canExecute()) {
					return candidate.getAbsolutePath();
				}
			}
		}
		return null;
	}
}

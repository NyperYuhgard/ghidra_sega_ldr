package sega.live;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * The emulator process, and the directory its trace appears in.
 * <p>
 * BlastEm opens its address log in its working directory rather than on standard output, so the
 * directory is chosen before the process starts and the reader knows which file to look at.
 */
public class BlastEmRunner {

	private static final long STOP_MILLIS = 2000;

	/**
	 * How the emulator is talked to about the memory it is running with. Both of the debuggers a
	 * BlastEm process can host take over the terminal and start the machine stopped at the reset
	 * vector, so choosing one of them changes what the process does with its three streams.
	 */
	public enum DebugChannel {

		/** No debugger: the game runs as soon as the process is up and nothing is written to it. */
		NONE,

		/**
		 * {@code -d -t}: the debugger of the emulator itself, spoken to with its own command lines.
		 * The second switch is what keeps those lines on the pipes of this process.
		 */
		NATIVE,

		/** {@code -D}, the remote stub read over its serial protocol on the process' own pipes. */
		REMOTE;
	}

	private final Path workingDirectory;

	/** What the emulator was asked to run, spelled the way a shell would take it. */
	private String commandLine = "";

	private Process process;

	/** Where the text of an emulator that speaks packets instead is kept out of the pipe. */
	private File stderrFile;

	private DebugChannel channel = DebugChannel.NONE;

	private OutputStream toEmulator;

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

	/** The log of the trace BlastEm is keeping: a disc gives one to each of its two 68000. */
	public File traceFile(String name) {
		return workingDirectory.resolve(name).toFile();
	}

	/** A file the emulator itself writes, like the memory image its debugger is asked to save. */
	public File workingFile(String name) {
		return workingDirectory.resolve(name).toFile();
	}

	public Path getWorkingDirectory() {
		return workingDirectory;
	}

	public DebugChannel getChannel() {
		return channel;
	}

	/** The text of an emulator running with {@code -D}: its messages cannot share the pipe. */
	public File getErrorFile() {
		return stderrFile;
	}

	/**
	 * Starts the emulator with the address log on.
	 *
	 * @param executable path to the blastem binary
	 * @param machine argument for {@code -m}, may be null to take the emulator's default
	 * @param rom the image to run
	 * @param extraArguments anything else the user types, split on spaces
	 * @param channel how the emulator is to be talked to about its memory
	 * @param outputSink receives every line the emulator prints, except through {@code REMOTE}
	 */
	public void start(String executable, String machine, String rom, String extraArguments,
			DebugChannel channel, Consumer<String> outputSink) throws IOException {

		List<String> command = new ArrayList<>();
		command.add(executable);
		if (machine != null && !machine.isBlank()) {
			command.add("-m");
			command.add(machine);
		}
		command.add("-l");
		switch (channel) {
			case NATIVE:
				command.add("-d");
				// Without -t the debugger of the emulator refuses a pipe for its terminal: it closes
				// the three streams of the process and carries its REPL off to a terminal window of
				// its own, over two named pipes (terminal.c).
				command.add("-t");
				break;
			case REMOTE:
				command.add("-D");
				break;
			default:
				break;
		}
		for (String argument : split(extraArguments)) {
			command.add(argument);
		}
		command.add(rom);
		commandLine = shown(command);

		ProcessBuilder builder = new ProcessBuilder(command);
		builder.directory(workingDirectory.toFile());
		if (channel == DebugChannel.REMOTE) {
			// The stub answers on standard output and, from this point on, nothing else is printed
			// there; the emulator's own text is sent where a person can still read it.
			stderrFile = workingFile("blastem-text.log");
			builder.redirectErrorStream(false);
			builder.redirectError(stderrFile);
			process = builder.start();
		}
		else {
			builder.redirectErrorStream(true);
			process = builder.start();
			pumpOutput(outputSink);
		}

		this.channel = channel;
		toEmulator = process.getOutputStream();
		if (channel == DebugChannel.NONE) {
			closeInput();
		}
	}

	/** One line of the debugger's own command language, as the emulator would be typed at it. */
	public void writeLine(String line) throws IOException {
		writeBytes(line + "\n");
	}

	/**
	 * One packet of the remote protocol. The stub ends a reply with its own framing, so nothing is
	 * read here; the reader of {@link #rawOutput()} is what takes the answer.
	 */
	public void sendPacket(String command) throws IOException {
		if (toEmulator == null) {
			throw new IOException("the emulator is not running");
		}
		writeBytes("$" + command + "#" + checksum(command));
	}

	/** Bytes of the protocol as they are, without the newline a line of the REPL wants. */
	public void writeBytes(String text) throws IOException {
		if (toEmulator == null) {
			throw new IOException("the emulator is not running");
		}
		toEmulator.write(text.getBytes(StandardCharsets.US_ASCII));
		toEmulator.flush();
	}

	/** The bytes the stub puts on standard output: packets, and nothing a person would read. */
	public InputStream rawOutput() {
		return process == null ? null : process.getInputStream();
	}

	/** The two hex digits the protocol asks for, although this stub does not look at them. */
	private static String checksum(String command) {
		int sum = 0;
		for (byte b : command.getBytes(StandardCharsets.US_ASCII)) {
			sum = (sum + (b & 0xff)) & 0xff;
		}
		return String.format("%02x", sum);
	}

	private void closeInput() {
		try {
			if (toEmulator != null) {
				toEmulator.close();
			}
		}
		catch (IOException e) {
			// A process that is going away does not care that its input is already gone.
		}
		toEmulator = null;
	}

	public String getCommandLine() {
		return commandLine;
	}

	/** The command as it would be typed, with the paths of a disc between their quotes. */
	private static String shown(List<String> command) {
		StringBuilder text = new StringBuilder();
		for (String part : command) {
			if (text.length() > 0) {
				text.append(' ');
			}
			text.append(part.contains(" ") ? "\"" + part + "\"" : part);
		}
		return text.toString();
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
		channel = DebugChannel.NONE;
		if (toEmulator != null) {
			// A debugger left with its terminal open holds the process on the last write.
			closeInput();
		}
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

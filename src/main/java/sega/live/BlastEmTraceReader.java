package sega.live;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.util.function.Consumer;
import java.util.function.LongConsumer;

/**
 * Reads BlastEm's {@code address.log} while the emulator runs.
 * <p>
 * {@code blastem -l} opens the file in its working directory and writes one address per translated
 * block, in uppercase hex and flushed on every line, so the file is a live feed rather than a
 * report written at exit.
 */
public class BlastEmTraceReader {

	private static final int READ_CHUNK = 64 * 1024;
	private static final long POLL_MILLIS = 40;

	/** How long to wait for the emulator to open its log. */
	private static final long START_WAIT_MILLIS = 10_000;

	/** Extra pause once the log appears, so a log left by an earlier run is truncated first. */
	private static final long START_SETTLE_MILLIS = 500;

	private final File file;
	private final LongConsumer addressHandler;
	private final Consumer<String> errorHandler;

	private volatile boolean running;
	private Thread thread;

	public BlastEmTraceReader(File file, LongConsumer addressHandler,
			Consumer<String> errorHandler) {
		this.file = file;
		this.addressHandler = addressHandler;
		this.errorHandler = errorHandler;
	}

	/** Follows the file from its current end; whatever it already holds is left alone. */
	public void startTail() {
		if (running) {
			return;
		}
		running = true;
		thread = new Thread(() -> run(true), "BlastEm trace");
		thread.setDaemon(true);
		thread.start();
	}

	/** Reads the whole file once, for a log saved by an earlier session. */
	public void readAll() {
		run(false);
	}

	private void run(boolean follow) {
		StringBuilder partial = new StringBuilder();
		byte[] buffer = new byte[READ_CHUNK];
		if (follow && !awaitFile()) {
			running = false;
			return;
		}
		try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
			long position = 0;
			while (running || !follow) {
				long length = raf.length();
				if (length < position) {
					// The emulator reopened the log: whatever came before belongs to another run.
					position = 0;
					partial.setLength(0);
				}
				if (position >= length) {
					if (!follow) {
						break;
					}
					sleep();
					continue;
				}
				raf.seek(position);
				int read = raf.read(buffer, 0, (int) Math.min(buffer.length, length - position));
				if (read <= 0) {
					if (!follow) {
						break;
					}
					sleep();
					continue;
				}
				position += read;
				consume(new String(buffer, 0, read, StandardCharsets.US_ASCII), partial);
			}
			if (!follow && partial.length() > 0) {
				accept(partial.toString());
			}
		}
		catch (IOException e) {
			if (follow && running) {
				errorHandler.accept("Lost the trace file: " + e.getMessage());
			}
			else if (!follow) {
				errorHandler.accept("Could not read " + file + ": " + e.getMessage());
			}
		}
		finally {
			if (follow) {
				running = false;
			}
		}
	}

	/**
	 * BlastEm opens the log while it boots, and truncates any log left by an earlier run at that
	 * moment, so following starts once the file is there and has settled.
	 *
	 * @return false when the emulator never produced a log or the session was stopped
	 */
	private boolean awaitFile() {
		long deadline = System.currentTimeMillis() + START_WAIT_MILLIS;
		while (running && !file.exists() && System.currentTimeMillis() < deadline) {
			sleep();
		}
		if (!running) {
			return false;
		}
		if (!file.exists()) {
			errorHandler.accept("BlastEm did not create " + file
				+ "; it was started without the address log, or it did not get as far as booting.");
			return false;
		}
		sleep(START_SETTLE_MILLIS);
		return true;
	}

	private void consume(String text, StringBuilder partial) {
		int start = 0;
		if (partial.length() > 0) {
			int end = text.indexOf('\n');
			if (end < 0) {
				// No break yet: keep the bytes so a torn address is never parsed.
				partial.append(text);
				return;
			}
			partial.append(text, 0, end);
			accept(partial.toString());
			partial.setLength(0);
			start = end + 1;
		}
		while (true) {
			int end = text.indexOf('\n', start);
			if (end < 0) {
				partial.append(text, start, text.length());
				return;
			}
			accept(text.substring(start, end));
			start = end + 1;
		}
	}

	private void accept(String line) {
		line = line.trim();
		if (line.isEmpty()) {
			return;
		}
		try {
			addressHandler.accept(Long.parseUnsignedLong(line, 16));
		}
		catch (NumberFormatException e) {
			errorHandler.accept("Unexpected text in the trace: " + line);
		}
	}

	private void sleep() {
		sleep(POLL_MILLIS);
	}

	private void sleep(long millis) {
		try {
			Thread.sleep(millis);
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			running = false;
		}
	}

	public void stop() {
		running = false;
		if (thread != null) {
			thread.interrupt();
			thread = null;
		}
	}

	public boolean isRunning() {
		return running;
	}
}

package sega.live;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * The remote stub of BlastEm, read as the protocol it speaks.
 * <p>
 * The framing is the one the emulator itself uses: a packet begins at {@code $}, ends two digits
 * after the {@code #}, and every byte between packets is thrown away in both directions. A request
 * the stub does not know ends the process there, so only the two packets that are known to be
 * handled are ever sent: read memory and continue.
 * <p>
 * A reply only arrives while the machine is stopped in its debugger. That is where a session with a
 * channel starts, and where it goes back when the {@code u} key is pressed, so a request that gets
 * nothing is answered with the truth rather than a guess.
 */
public class RspChannel {

	/** What one read packet carries: the emulator answers with at most this many bytes. */
	public static final int MAX_CHUNK = 255;

	/** How long a request waits before the answer is "the machine is not stopped". */
	private static final int WAIT_MILLIS = 3000;

	private static final int HEX_DIGITS = 2;

	private final BlastEmRunner runner;
	private final byte[] buffer = new byte[8192];
	private int length;

	private Thread pump;

	private final Object traffic = new Object();

	public RspChannel(BlastEmRunner runner) {
		this.runner = runner;
		InputStream raw = runner.rawOutput();
		pump = new Thread(() -> readForever(raw), "BlastEm remote stub");
		pump.setDaemon(true);
		pump.start();
	}

	private void readForever(InputStream raw) {
		byte[] chunk = new byte[1024];
		try {
			int read;
			while ((read = raw.read(chunk)) > 0) {
				append(chunk, read);
			}
		}
		catch (IOException e) {
			// The process going away is the end of the channel; the session reports it on its own.
		}
		synchronized (traffic) {
			pump = null;
			traffic.notifyAll();
		}
	}

	private void append(byte[] chunk, int count) {
		synchronized (traffic) {
			if (length + count > buffer.length) {
				// Keep the newest bytes: an old request nobody can answer any more is of no use.
				int drop = length + count - buffer.length;
				System.arraycopy(buffer, drop, buffer, 0, length - drop);
				length -= drop;
			}
			System.arraycopy(chunk, 0, buffer, length, count);
			length += count;
			traffic.notifyAll();
		}
	}

	/**
	 * The memory the emulator is standing on, asked for in pieces of what one packet can carry.
	 *
	 * @throws IOException when the stub refuses, or is not listening because the machine runs
	 */
	public byte[] readMemory(long address, int size) throws IOException {
		byte[] data = new byte[size];
		int done = 0;
		while (done < size) {
			int want = Math.min(MAX_CHUNK, size - done);
			String digits = request("m" + Long.toHexString(address + done) + ","
				+ Integer.toHexString(want));
			if (digits.length() < want * HEX_DIGITS) {
				throw new IOException(String.format(
					"the emulator answered with %d of the %d byte(s) asked for at 0x%X",
					digits.length() / HEX_DIGITS, want, address + done));
			}
			for (int i = 0; i < want; i++) {
				data[done + i] =
					(byte) Integer.parseInt(digits.substring(i * HEX_DIGITS, i * HEX_DIGITS + 2), 16);
			}
			done += want;
		}
		return data;
	}

	/** Tells the stub to let the machine run again. Nothing is waited for, because nothing answers. */
	public void resume() throws IOException {
		runner.sendPacket("c");
	}

	/**
	 * One request and its reply, with a stop reply of the machine itself discarded on the way.
	 *
	 * @param command the packet without its framing, like {@code mff0000,100}
	 */
	private String request(String command) throws IOException {
		runner.sendPacket(command);
		long deadline = System.currentTimeMillis() + WAIT_MILLIS;
		while (true) {
			String packet = awaitPacket(deadline);
			char kind = packet.isEmpty() ? 0 : packet.charAt(0);
			if (kind == 'T' || kind == 'S') {
				// The machine saying it stopped is not an answer; it only says it is listening.
				continue;
			}
			if (kind == 'E' && packet.length() == HEX_DIGITS + 1) {
				throw new IOException("the emulator refused the request with code "
					+ packet.substring(1));
			}
			return packet;
		}
	}

	/** The next whole packet, with anything that is not framing thrown away. */
	private String awaitPacket(long deadline) throws IOException {
		synchronized (traffic) {
			while (true) {
				int start = indexOf('$', 0);
				if (start > 0) {
					consume(start);
					continue;
				}
				if (start == 0) {
					int end = indexOf('#', 1);
					if (end >= 0 && end + HEX_DIGITS + 1 <= length) {
						String packet =
							new String(buffer, 1, end - 1, StandardCharsets.US_ASCII);
						consume(end + HEX_DIGITS + 1);
						acknowledge();
						return packet;
					}
				}
				else if (length > 0) {
					// Nothing in the traffic is a packet yet, and none of it will ever be one.
					consume(length);
				}

				long left = deadline - System.currentTimeMillis();
				if (left <= 0 || pump == null) {
					throw new IOException("BlastEm is not stopped in its debugger, so the request is "
						+ "only buffered: press the u key in the emulator window, or let a breakpoint "
						+ "stop the machine, and ask again.");
				}
				try {
					traffic.wait(left);
				}
				catch (InterruptedException e) {
					Thread.currentThread().interrupt();
					throw new IOException("the request was given up on");
				}
			}
		}
	}

	/** The acknowledgement a stub expecting one sends nothing back for. */
	private void acknowledge() {
		try {
			runner.writeBytes("+");
		}
		catch (IOException e) {
			// Losing an acknowledgement costs the reply that was already in hand, and nothing else.
		}
	}

	private int indexOf(char needle, int from) {
		for (int i = from; i < length; i++) {
			if (buffer[i] == needle) {
				return i;
			}
		}
		return -1;
	}

	private void consume(int count) {
		System.arraycopy(buffer, count, buffer, 0, length - count);
		length -= count;
	}

	public void close() {
		if (pump != null) {
			pump.interrupt();
		}
	}
}

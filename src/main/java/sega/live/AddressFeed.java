package sega.live;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Addresses the emulator has reached, gathered between two runs of the analyzer.
 * <p>
 * A loop in the game's sound driver offers the same handful of blocks hundreds of times a second,
 * so the feed remembers what it has already handed over and only passes each address once. The
 * history is dropped when the program or the filtering changes, because an address that was
 * skipped under one setting may be worth looking at under another.
 */
public class AddressFeed {

	private static final int MAX_REMEMBERED = 1 << 20;

	private final Set<Long> pending = new LinkedHashSet<>();
	private final Set<Long> handed = new HashSet<>();

	private long total;

	/** @return false when the address was already handed to the analyzer */
	public synchronized boolean offer(long address) {
		total++;
		if (handed.contains(address) || !pending.add(address)) {
			return false;
		}
		if (handed.size() < MAX_REMEMBERED) {
			handed.add(address);
		}
		return true;
	}

	public synchronized boolean hasPending() {
		return !pending.isEmpty();
	}

	public synchronized int pendingCount() {
		return pending.size();
	}

	/** @return up to {@code max} addresses in the order they were reached, leaving the rest queued */
	public synchronized List<Long> drain(int max) {
		List<Long> batch = new ArrayList<>(Math.min(max, pending.size()));
		var iterator = pending.iterator();
		while (iterator.hasNext() && batch.size() < max) {
			batch.add(iterator.next());
			iterator.remove();
		}
		return batch;
	}

	/** Every address the emulator has logged since it started. */
	public synchronized long totalCount() {
		return total;
	}

	public synchronized void forget() {
		pending.clear();
		handed.clear();
		total = 0;
	}
}

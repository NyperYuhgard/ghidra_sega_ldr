package sega.live;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.filechooser.ExtensionFileFilter;

/**
 * The panel that drives the live session: what to run, how to filter it, and what came of it.
 */
public class BlastEmLiveProvider extends ComponentProviderAdapter {

	/**
	 * The machine names BlastEm's {@code -m} accepts, with what they mean. An empty id leaves the
	 * switch out and lets the emulator read the image, which is the only way to reach a Sega CD disc.
	 */
	private static final String[][] MACHINES = {
		{ "", "Detect from the image" },
		{ "gen", "Mega Drive / Genesis (68000)" },
		{ "32x", "32X (68000 + two SH-2)" },
		{ "32xcd", "32X over a Sega CD disc" },
		{ "pico", "Pico (68000)" },
		{ "copera", "Copera (68000)" },
		{ "sms", "Master System (Z80)" },
		{ "gg", "Game Gear (Z80)" },
		{ "sg", "SG-1000 (Z80)" },
		{ "sc", "SC-3000 (Z80)" },
		{ "media", "Media player (VGM / WAV / FLAC, no CPU to trace)" },
		{ "laser", "LaserActive (NEC UPD78K237, no trace)" },
	};

	/** What the panel asks the plugin to do. */
	public interface Controls {

		void start(BlastEmLiveProvider settings);

		void stop();

		void ingestFile(String path, BlastEmLiveProvider settings);

		/** The filter changed: addresses already passed over may deserve a second look. */
		void settingsChanged();
	}

	private static final int LOG_LINES = 400;

	private final Controls controls;

	private JTextField romField;
	private JTextField executableField;
	private JComboBox<String> machineBox;
	private JComboBox<String> modeBox;
	private JTextField workingDirectoryField;
	private JTextField argumentsField;
	private JCheckBox ramCheck;
	private JCheckBox followPcCheck;
	private JCheckBox pauseCheck;
	private JButton startButton;
	private JButton stopButton;
	private JButton browseRomButton;
	private JButton browseExecutableButton;
	private JButton browseFolderButton;
	private JButton ingestButton;
	private JTextArea logArea;
	private JLabel countsLabel;

	private String selectedMachineId = "";
	private IngestCommand.Mode selectedMode = IngestCommand.Mode.ANALYSIS_QUEUE;

	private JComponent component;

	/** The panel keeps its own copy of these until the window is shown for the first time. */
	private String romText = "";
	private String countsText = "idle";
	private boolean running;
	private final List<String> messages = new ArrayList<>();

	public BlastEmLiveProvider(PluginTool tool, Controls controls) {
		super(tool, "BlastEm Live", "Sega");
		this.controls = controls;
	}

	@Override
	public JComponent getComponent() {
		if (component == null) {
			JPanel panel = new JPanel(new BorderLayout());
			panel.add(buildForm(), BorderLayout.NORTH);
			panel.add(buildLog(), BorderLayout.CENTER);
			panel.add(buildCounts(), BorderLayout.SOUTH);
			showState();
			component = panel;
		}
		return component;
	}

	/**
	 * Moves what the panel has been keeping into widgets that are only now coming into existence:
	 * the program is activated as soon as it opens, whether or not this window was ever shown.
	 */
	private void showState() {
		romField.setText(romText);
		countsLabel.setText(countsText);
		setRunning(running);
		for (String message : messages) {
			logArea.append(message);
			logArea.append("\n");
		}
		logArea.setCaretPosition(logArea.getDocument().getLength());
	}

	@Override
	public String getTitle() {
		return "BlastEm Live";
	}

	private JComponent buildForm() {
		JPanel form = new JPanel(new GridBagLayout());
		form.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
		GridBagConstraints at = new GridBagConstraints();
		at.insets = new Insets(2, 2, 2, 2);
		at.anchor = GridBagConstraints.WEST;
		at.fill = GridBagConstraints.HORIZONTAL;

		romField = new JTextField(24);
		executableField = new JTextField(defaultExecutable(), 24);
		machineBox = new JComboBox<>(machineLabels());
		machineBox.setSelectedIndex(machineIndexOf(""));
		machineBox.addActionListener(e -> selectedMachineId = machineIdAt(machineBox.getSelectedIndex()));
		workingDirectoryField = new JTextField(24);
		argumentsField = new JTextField(24);

		modeBox = new JComboBox<>(modeLabels());
		modeBox.setToolTipText("How the logged addresses become code.\n"
			+ "  · auto analysis: every batch goes into the analyzer's queue and the listing fills\n"
			+ "    when the tool is idle. The most complete result, and the slowest to show.\n"
			+ "  · immediate: the batch is disassembled inside its own transaction, at once, and the\n"
			+ "    analyzers review all of the new code in one pass when you press Stop.\n"
			+ "  · disassemble only: as quick as the above, and no analysis is asked for; you run\n"
			+ "    Analyze yourself whenever you like.\n"
			+ "The last two are experimental: instructions appear right away, but a function may take\n"
			+ "a while to look complete.");
		modeBox.addActionListener(e -> selectedMode = modeAt(modeBox.getSelectedIndex()));

		browseRomButton = new JButton("…");
		browseRomButton.setToolTipText(
			"The image BlastEm runs; it is filled with the file this program was imported from.");
		browseRomButton.addActionListener(e -> choose(romField, GhidraFileChooserMode.FILES_ONLY));

		browseExecutableButton = new JButton("…");
		browseExecutableButton.setToolTipText("The blastem binary; left empty it is taken from PATH.");
		browseExecutableButton.addActionListener(
			e -> choose(executableField, GhidraFileChooserMode.FILES_ONLY));

		browseFolderButton = new JButton("…");
		browseFolderButton.setToolTipText("Where BlastEm writes address.log. It also keeps its save files "
			+ "in the folder it runs from, so point this at the directory holding your saves to carry on using them. "
			+ "Left empty, a fresh temporary folder is used.");
		browseFolderButton.addActionListener(
			e -> choose(workingDirectoryField, GhidraFileChooserMode.DIRECTORIES_ONLY));

		machineBox.setToolTipText("BlastEm reads the console from the image, so detecting is usually right.\n"
			+ "Master System and Game Gear are told apart by the file extension, so name a Game Gear image .gg.\n"
			+ "Only the 68000 machines give Ghidra a trace: BlastEm logs no addresses for the Z80 of the\n"
			+ "Master System and friends, nor for the NEC CPU of the LaserActive.");

		at.gridx = 0;
		at.gridy = 0;
		at.weightx = 0;
		form.add(new JLabel("ROM"), at);
		at.gridx = 1;
		at.weightx = 1;
		form.add(romField, at);
		at.gridx = 2;
		at.weightx = 0;
		form.add(browseRomButton, at);

		at.gridx = 0;
		at.gridy = 1;
		form.add(new JLabel("BlastEm"), at);
		at.gridx = 1;
		at.weightx = 1;
		form.add(executableField, at);
		at.gridx = 2;
		at.weightx = 0;
		form.add(browseExecutableButton, at);

		at.gridx = 0;
		at.gridy = 2;
		form.add(new JLabel("Machine"), at);
		at.gridx = 1;
		at.gridwidth = 2;
		at.weightx = 1;
		form.add(machineBox, at);
		at.gridwidth = 1;

		at.gridx = 0;
		at.gridy = 3;
		at.weightx = 0;
		form.add(new JLabel("Disassemble"), at);
		at.gridx = 1;
		at.gridwidth = 2;
		at.weightx = 1;
		form.add(modeBox, at);
		at.gridwidth = 1;

		at.gridx = 0;
		at.gridy = 4;
		at.weightx = 0;
		form.add(new JLabel("Trace folder"), at);
		at.gridx = 1;
		at.weightx = 1;
		form.add(workingDirectoryField, at);
		at.gridx = 2;
		at.weightx = 0;
		form.add(browseFolderButton, at);

		at.gridx = 0;
		at.gridy = 5;
		at.weightx = 0;
		form.add(new JLabel("Extra args"), at);
		at.gridx = 1;
		at.gridwidth = 2;
		at.weightx = 1;
		form.add(argumentsField, at);
		at.gridwidth = 1;

		ramCheck = new JCheckBox("RAM too", false);
		ramCheck.setToolTipText("Take the addresses that land in work or battery RAM as code too. "
			+ "Useful for patchers and for routines the game loads into RAM, noisy otherwise.");
		ramCheck.addActionListener(e -> controls.settingsChanged());

		followPcCheck = new JCheckBox("follow the PC", false);
		followPcCheck.setToolTipText("Move the listing cursor to the last address the emulator reached.");

		pauseCheck = new JCheckBox("pause", false);
		pauseCheck.setToolTipText("Keep the emulator running and keep counting, without touching the program.");

		startButton = new JButton("Start");
		startButton.addActionListener(e -> controls.start(this));
		stopButton = new JButton("Stop");
		stopButton.addActionListener(e -> controls.stop());
		stopButton.setEnabled(false);
		ingestButton = new JButton("Ingest log…");
		ingestButton.addActionListener(e -> chooseTraceLog());

		JPanel buttons = new JPanel();
		buttons.setLayout(new BoxLayout(buttons, BoxLayout.X_AXIS));
		buttons.add(startButton);
		buttons.add(Box.createHorizontalStrut(6));
		buttons.add(stopButton);
		buttons.add(Box.createHorizontalStrut(6));
		buttons.add(ingestButton);

		JPanel checks = new JPanel();
		checks.setLayout(new BoxLayout(checks, BoxLayout.X_AXIS));
		checks.add(ramCheck);
		checks.add(Box.createHorizontalStrut(12));
		checks.add(followPcCheck);
		checks.add(Box.createHorizontalStrut(12));
		checks.add(pauseCheck);

		at.gridx = 0;
		at.gridy = 6;
		at.gridwidth = 3;
		form.add(checks, at);
		at.gridy = 7;
		form.add(buttons, at);
		at.gridwidth = 1;

		return form;
	}

	private JComponent buildLog() {
		logArea = new JTextArea();
		logArea.setEditable(false);
		logArea.setFont(new java.awt.Font("Monospaced", java.awt.Font.PLAIN, 12));
		logArea.setLineWrap(false);
		JScrollPane scroll = new JScrollPane(logArea);
		scroll.setPreferredSize(new Dimension(480, 180));
		scroll.setBorder(BorderFactory.createTitledBorder("Trace"));
		return scroll;
	}

	private JComponent buildCounts() {
		countsLabel = new JLabel("idle");
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));
		panel.add(countsLabel, BorderLayout.WEST);
		return panel;
	}

	private void chooseTraceLog() {
		GhidraFileChooser chooser = new GhidraFileChooser(tool.getActiveWindow());
		chooser.setSelectedFileFilter(new ExtensionFileFilter("BlastEm traces", "log"));
		chooser.setApproveButtonText("Ingest");
		File selected = chooser.getSelectedFile();
		if (selected != null) {
			controls.ingestFile(selected.getAbsolutePath(), this);
		}
	}

	private void choose(JTextField field, GhidraFileChooserMode mode) {
		GhidraFileChooser chooser = new GhidraFileChooser(tool.getActiveWindow());
		chooser.setFileSelectionMode(mode);
		chooser.setApproveButtonText("Choose");
		if (!field.getText().isBlank()) {
			chooser.setSelectedFile(new File(field.getText()));
		}
		File selected = chooser.getSelectedFile();
		if (selected != null) {
			field.setText(selected.getAbsolutePath());
		}
	}

	/** Fills the ROM field from the program the user is looking at. */
	public void setProgram(Program program) {
		String path = program == null ? null : program.getExecutablePath();
		romText = path == null ? "" : path;
		if (romField != null) {
			romField.setText(romText);
		}
	}

	public String getRomPath() {
		return (romField == null ? romText : romField.getText()).trim();
	}

	public String getExecutablePath() {
		String path = executableField == null ? "" : executableField.getText().trim();
		if (path.isEmpty()) {
			String found = BlastEmRunner.findOnPath("blastem", "blastem.exe");
			return found == null ? "blastem" : found;
		}
		return path;
	}

	public String getMachine() {
		return selectedMachineId;
	}

	/** How the user wants the logged addresses turned into code. */
	public IngestCommand.Mode getMode() {
		return selectedMode;
	}

	public String getWorkingDirectory() {
		return workingDirectoryField == null ? "" : workingDirectoryField.getText().trim();
	}

	public String getExtraArguments() {
		return argumentsField == null ? "" : argumentsField.getText().trim();
	}

	public boolean isIncludingRam() {
		return ramCheck != null && ramCheck.isSelected();
	}

	public boolean isFollowingPc() {
		return followPcCheck != null && followPcCheck.isSelected();
	}

	public boolean isPaused() {
		return pauseCheck != null && pauseCheck.isSelected();
	}

	public void setRunning(boolean running) {
		this.running = running;
		if (startButton == null) {
			return;
		}
		startButton.setEnabled(!running);
		stopButton.setEnabled(running);
		romField.setEnabled(!running);
		machineBox.setEnabled(!running);
		modeBox.setEnabled(!running);
		executableField.setEnabled(!running);
		workingDirectoryField.setEnabled(!running);
		argumentsField.setEnabled(!running);
	}

	public void setCounts(String text) {
		countsText = text;
		if (countsLabel != null) {
			countsLabel.setText(countsText);
		}
	}

	/** Safe from any thread: the log belongs to Swing. */
	public void log(String message) {
		if (SwingUtilities.isEventDispatchThread()) {
			append(message);
		}
		else {
			SwingUtilities.invokeLater(() -> append(message));
		}
	}

	private void append(String message) {
		messages.add(message);
		while (messages.size() > LOG_LINES) {
			messages.remove(0);
		}
		if (logArea == null) {
			return;
		}
		logArea.append(message);
		logArea.append("\n");
		if (logArea.getLineCount() > LOG_LINES) {
			try {
				int start = logArea.getLineStartOffset(logArea.getLineCount() - LOG_LINES);
				logArea.replaceRange(null, 0, start);
			}
			catch (javax.swing.text.BadLocationException e) {
				// Only ever thrown for an offset we just read from the same document.
			}
		}
		logArea.setCaretPosition(logArea.getDocument().getLength());
	}

	private static final String[] MODE_LABELS = { "auto analysis", "immediate (experimental)",
		"disassemble only (experimental)" };

	private static String[] modeLabels() {
		return MODE_LABELS.clone();
	}

	private static IngestCommand.Mode modeAt(int index) {
		return switch (index) {
			case 1 -> IngestCommand.Mode.DIRECT;
			case 2 -> IngestCommand.Mode.DISASSEMBLE_ONLY;
			default -> IngestCommand.Mode.ANALYSIS_QUEUE;
		};
	}

	static String modeLabel(IngestCommand.Mode mode) {
		return switch (mode) {
			case ANALYSIS_QUEUE -> MODE_LABELS[0];
			case DIRECT -> MODE_LABELS[1];
			case DISASSEMBLE_ONLY -> MODE_LABELS[2];
		};
	}

	private static String[] machineLabels() {
		String[] labels = new String[MACHINES.length];
		for (int i = 0; i < MACHINES.length; i++) {
			labels[i] = MACHINES[i][1];
		}
		return labels;
	}

	private static int machineIndexOf(String id) {
		for (int i = 0; i < MACHINES.length; i++) {
			if (MACHINES[i][0].equals(id)) {
				return i;
			}
		}
		return 0;
	}

	private static String machineIdAt(int index) {
		return MACHINES[index][0];
	}

	private static String defaultExecutable() {
		String found = BlastEmRunner.findOnPath("blastem", "blastem.exe");
		return found == null ? "" : found;
	}
}

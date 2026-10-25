/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sega;

import java.awt.Component;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.util.List;
import java.util.function.Consumer;

import javax.swing.JComboBox;

import ghidra.app.util.Option;
import ghidra.framework.options.SaveState;

/**
 * A word of text that the image being imported can answer with, offered as the list it holds rather
 * than as a field to type into. What the box shows is read off the file, so nothing in it is
 * invented, and it stays open to whatever is typed: a name outside the list still means the same to
 * a command line.
 */
class ListOption extends Option {

	private final String group;
	private final String argument;
	private final String stateKey;
	private final List<String> choices;

	ListOption(String name, String value, String group, String argument, String stateKey,
			List<String> choices) {
		super(name, String.class, value, argument, group, stateKey, false);
		this.group = group;
		this.argument = argument;
		this.stateKey = stateKey;
		this.choices = List.copyOf(choices);
	}

	@Override
	public Component getCustomEditorComponent() {
		SaveState state = getState();
		String remembered = state == null ? null : state.getString(getName(), null);
		JComboBox<String> box = new JComboBox<>(choices.toArray(new String[0]));
		box.setEditable(true);
		Object value = getValue();
		String shown = remembered != null ? remembered : value == null ? "" : value.toString();
		box.setSelectedItem(shown);
		if (!shown.equals(value)) {
			// What the box shows is what the import gets, remembered or not.
			setValue(shown);
		}
		// Picking an entry answers the box; a name typed into it only answers when the box is left,
		// which the dialog does not notice on its own.
		Consumer<String> answered = text -> {
			setValue(text);
			if (state != null) {
				state.putString(getName(), text);
			}
		};
		box.addActionListener(e -> answered.accept(asWritten(box)));
		box.addFocusListener(new FocusListener() {
			@Override
			public void focusLost(FocusEvent e) {
				answered.accept(asWritten(box));
			}

			@Override
			public void focusGained(FocusEvent e) {
			}
		});
		return box;
	}

	@Override
	public Option copy() {
		return new ListOption(getName(), (String) getValue(), group, argument, stateKey, choices);
	}

	private static String asWritten(JComboBox<String> box) {
		Object written = box.getEditor().getItem();
		return written == null ? "" : written.toString().trim();
	}
}

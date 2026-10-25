package sega;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.InvalidInputException;

/**
 * The structures the loaders lay over an image. Every one of them carries the category it lives in,
 * so a project that imports two cartridges of the same family holds one definition of each and not
 * one per import.
 */
final class SegaDataTypes {

	static final CategoryPath SEGA = new CategoryPath("/Sega");
	static final CategoryPath SEGA_CD = new CategoryPath("/Sega/Sega CD");

	private SegaDataTypes() {
	}

	/**
	 * Puts a structure in the catalogue of the program and answers with the version the catalogue
	 * keeps. A type of the same name that is already there is left alone, whoever wrote it.
	 */
	static DataType register(Program program, DataType type) {
		DataTypeManager dtm = program.getDataTypeManager();
		CategoryPath path = type.getCategoryPath();
		DataType existing = dtm.getDataType(path, type.getName());
		if (existing != null) {
			return existing;
		}
		dtm.createCategory(path);
		return dtm.addDataType(type, DataTypeConflictHandler.KEEP_HANDLER);
	}

	/**
	 * Defines a structure over the memory of the program and names it. Answers whether the listing
	 * took it: memory already claimed by something else is reported, never overwritten silently.
	 */
	static boolean apply(Program program, Address at, DataType type, String label, MessageLog log) {
		DataType stored = register(program, type);
		try {
			DataUtilities.createData(program, at, stored, -1, false,
				ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
		}
		catch (CodeUnitInsertionException e) {
			log.appendMsg(stored.getName() + " at " + at + ": " + e.getMessage());
			return false;
		}
		if (label != null) {
			try {
				program.getSymbolTable().createLabel(at, label, SourceType.IMPORTED);
			}
			catch (InvalidInputException e) {
				log.appendMsg(label + ": " + e.getMessage());
			}
		}
		return true;
	}
}

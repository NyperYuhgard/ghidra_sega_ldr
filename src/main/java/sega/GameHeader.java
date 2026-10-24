package sega;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

class GameHeader implements StructConverter {

	/** Offset of the console name inside the header. */
	static final long HEADER_ADDRESS = 0x100;

	/** The 68000 only sees the low 23 bits of a backup RAM address, and accesses are word sized. */
	private static final long SRAM_ADDRESS_MASK = 0xFFFFFEL;
	private static final int SRAM_MODE_MASK = 0x18;
	private static final int SRAM_MODE_ODD = 0x18;
	private static final int SRAM_MODE_EVEN = 0x10;

	private byte[] consoleName = null;
    private byte[] releaseDate = null;
    private byte[] domesticName = null;
    private byte[] internationalName = null;
    private byte[] version = null;
    private short checksum = 0;
    private byte[] ioSupport = null;
    private long romStart = 0, romEnd = 0;
    private long ramStart = 0, ramEnd = 0;
    private byte[] sramCode = null;
    private byte sramFlags = 0;
    private long sramStart = 0, sramEnd = 0;
    private byte[] notes = null;
    private byte[] regionCodes = null;
    
    GameHeader(BinaryReader reader) throws IOException {
        
        if (reader.length() < 0x200) {
            return;
        }
        
        reader.setPointerIndex(0x100);
        
        consoleName = reader.readNextByteArray(0x10);
        releaseDate = reader.readNextByteArray(0x10);
        domesticName = reader.readNextByteArray(0x30);
        internationalName = reader.readNextByteArray(0x30);
        version = reader.readNextByteArray(0x0E);
        checksum = (short) reader.readNextUnsignedShort();
        ioSupport = reader.readNextByteArray(0x10);
        romStart = reader.readNextUnsignedInt();
        romEnd = reader.readNextUnsignedInt();
        ramStart = reader.readNextUnsignedInt();
        ramEnd = reader.readNextUnsignedInt();
        sramCode = reader.readNextByteArray(0x03);
        sramFlags = reader.readNextByte();
        sramStart = reader.readNextUnsignedInt();
        sramEnd = reader.readNextUnsignedInt();
        // 0x1BC..0x1FF are the supported regions, 0x1F0..0x1FF the region codes ("JUE", "JA", ...)
        notes = reader.readNextByteArray(0x34);
        regionCodes = reader.readNextByteArray(0x10);
    }
    
    @Override
    public DataType toDataType() {
        Structure s = new StructureDataType("GameHeader", 0);
        
        s.add(STRING, 0x10, "ConsoleName", null);
        s.add(STRING, 0x10, "ReleaseDate", null);
        s.add(STRING, 0x30, "DomesticName", null);
        s.add(STRING, 0x30, "InternationalName", null);
        s.add(STRING, 0x0E, "Version", null);
        s.add(WORD, 0x02, "Checksum", null);
        s.add(STRING, 0x10, "IoSupport", null);
        s.add(POINTER, 0x04, "RomStart", null);
        s.add(POINTER, 0x04, "RomEnd", null);
        s.add(POINTER, 0x04, "RamStart", null);
        s.add(POINTER, 0x04, "RamEnd", null);
        s.add(STRING, 0x03, "SramCode", null);
        s.add(BYTE, 0x01, "SramFlags", null);
        s.add(POINTER, 0x04, "SramStart", null);
        s.add(POINTER, 0x04, "SramEnd", null);
        s.add(STRING, 0x34, "Notes", null);
        s.add(STRING, 0x10, "RegionCodes", null);
        
        return s;
    }
    
    public byte[] getConsoleName() {
        return consoleName;
    }
    
    public byte[] getReleaseDate() {
        return releaseDate;
    }
    
    public byte[] getDomesticName() {
        return domesticName;
    }
    
    public byte[] getInternationalName() {
        return internationalName;
    }
    
    public byte[] getVersion() {
    	return version;
    }
    
    public short getChecksum() {
        return checksum;
    }
    
    public byte[] getIoSupport() {
        return ioSupport;
    }
    
    public long getRomStart() {
        return romStart;
    }
    
    public long getRomEnd() {
        return romEnd;
    }
    
    public long getRamStart() {
        return ramStart;
    }
    
    public long getRamEnd() {
        return ramEnd;
    }
    
    public byte[] getSramCode() {
        return sramCode;
    }
    
    public byte getSramFlags() {
    	return sramFlags;
    }
    
    public long getSramStart() {
        return sramStart;
    }
    
    public long getSramEnd() {
        return sramEnd;
    }

    /** First address of the backup RAM, as the cartridge decodes it. */
    public long getBackupRamStart() {
        return sramStart & SRAM_ADDRESS_MASK;
    }

    /** Last address of the backup RAM, as the cartridge decodes it. */
    public long getBackupRamEnd() {
        return (sramEnd | 1) & 0xFFFFFFL;
    }

    /**
     * The SRAM code ("RA") is the only signal the cartridge looks at; the third byte is a size
     * hint that homebrew tends to get wrong.
     */
    public boolean hasSRAM() {
        return sramCode != null && sramCode[0] == (byte)'R' && sramCode[1] == (byte)'A';
    }

    /**
     * Half of the bus the battery RAM is wired to. A cart may answer on the odd or on the even
     * bytes of the window it declares, and the other half then belongs to whatever else lives
     * there; only both halves exist when the mode field is clear.
     */
    public String getBackupRamMode() {
        int mode = sramFlags & SRAM_MODE_MASK;
        return mode == SRAM_MODE_ODD ? "odd" : mode == SRAM_MODE_EVEN ? "even" : "both";
    }

    public boolean isPresent() {
        return consoleName != null && ascii(consoleName).startsWith("SEGA");
    }

    public String getRegionCodes() {
        return ascii(regionCodes);
    }

    static String ascii(byte[] bytes) {
        String text = new String(bytes, StandardCharsets.US_ASCII);
        int end = text.length();
        while (end > 0 && (text.charAt(end - 1) == ' ' || text.charAt(end - 1) == '\0')) {
            end--;
        }
        return text.substring(0, end);
    }
    
    public byte[] getNotes() {
        return notes;
    }
}

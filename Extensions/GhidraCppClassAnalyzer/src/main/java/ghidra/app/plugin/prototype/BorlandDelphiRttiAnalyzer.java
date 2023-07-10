package ghidra.app.plugin.prototype;

import ghidra.app.cmd.data.rtti.borland.delphi.datatype.*;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.InvalidNameException;
import ghidra.util.bytesearch.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import org.apache.commons.lang3.ArrayUtils;

import java.lang.Byte;
import java.util.*;

public class BorlandDelphiRttiAnalyzer extends AbstractAnalyzer {

	public static final String ANALYZER_NAME = "Borland Delphi RTTI Analyzer";
	private static final String DESCRIPTION =
		"This analyzer finds and creates all of the RTTI metadata structures and their associated vtables.";
	private Program program;
	private AddressSetView set;
	private TaskMonitor monitor;
	private MessageLog log;
	private Listing listing;
	private Memory memory;
	private boolean bigEndian;
	private ProgramBasedDataTypeManager dataTypeManager;
	private CategoryPath systemPath;
	private EnumDataType TTypeKindDT;
	private StructureDataType TTypeInfoDT;
	private PascalString255DataType StringDT;
	private PointerDataType PointerDT;
	private StructureDataType TVmtDT;
	private SymbolTable symbolTable;
	RelocationTable relocationTable;
	List<Relocation> relocations;
	List<Address> pending;
	List<Address> ready;

	public BorlandDelphiRttiAnalyzer() {
		super(ANALYZER_NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
	}

	@Override
	public boolean canAnalyze(Program program) {
		String compilerIdString = program.getCompilerSpec().getCompilerSpecID().getIdAsString().toLowerCase();
		return compilerIdString.equals("borlanddelphi");
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
		throws CancelledException {
		if (!init(program, set, monitor, log)) return false;
		Address vmtAddress = getTObjectVmt();
		if (vmtAddress == null) return false;
		Address selfPtr = readPointer(vmtAddress);
		if (selfPtr == null) return false;
		long diff = selfPtr.subtract(vmtAddress);
		TVmtDT = TVmt.getDataType(systemPath, dataTypeManager, diff);
		putVirtualMethodTable(vmtAddress);
		createLabel(vmtAddress, "VMT_" + TVmt.getVMTTypeName(vmtAddress, program));
		pending.add(vmtAddress);
		while (!pending.isEmpty()) {
			Address parent = pending.remove(0);
			if (ready.contains(parent)) continue;
			List<Address> children = getChildren(parent);
			pending.addAll(children);
			ready.add(parent);
		}
		return true;
	}

	private boolean init(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {
		this.program = program;
		this.set = set;
		this.monitor = monitor;
		this.log = log;

		listing = program.getListing();
		memory = program.getMemory();
		bigEndian = program.getLanguage().isBigEndian();
		dataTypeManager = program.getDataTypeManager();
		try {
			systemPath = dataTypeManager.getCategory(CategoryPath.ROOT).createCategory("system.pas").getCategoryPath();
		} catch (InvalidNameException e) {
			return false;
		}
		StringDT = PascalString255DataType.dataType;
		String compilerVersion = getCompilerVersion();
		if (compilerVersion == null) {
			return false;
		}

		TTypeKindDT = TTypeKind.getDataType(systemPath, dataTypeManager);
		TTypeInfoDT = TTypeInfo.getDataType(systemPath, dataTypeManager);
		PointerDT = PointerDataType.dataType;

		relocationTable = program.getRelocationTable();
		Iterator<Relocation> iterator = relocationTable.getRelocations();
		relocations = new ArrayList<>();
		while (iterator.hasNext()) {
			Relocation relocation = iterator.next();
			relocations.add(relocation);
		}
		symbolTable = program.getSymbolTable();
		ready = new LinkedList<>();
		pending = new LinkedList<>();
		return true;
	}

	private String getCompilerVersion() {
		MemoryBlock rdata = memory.getBlock(".rdata");
		if (rdata == null) return null;
		Address address = rdata.getStart();
		String string = readCString(address);
		if (string == null) return null;
		String searchString = "compiler version";
		if (!string.contains(searchString)) return null;
		String versionString = string.substring(string.indexOf(searchString) + searchString.length());
		if (!versionString.contains("(")) return null;
		versionString = versionString.substring(0, versionString.indexOf("("));
		versionString = versionString.replace(" ", ""); // Delete extra space chars
		Data data = deleteCreateData(address, TerminatedStringDataType.dataType);
		return versionString;
	}

	private void putTTypeInfo(Address address) {
		deleteCreateData(address, TTypeInfoDT);
		deleteCreateData(address.add(TTypeInfoDT.getLength()), PascalString255DataType.dataType);
	}

	private void putVirtualMethodTable(Address address) {
		deleteCreateData(address, TVmtDT);
		long pointerSize = PointerDT.getLength();
		Address vmtTypeInfo = readPointer(address.add(pointerSize * 4));
		putTTypeInfo(vmtTypeInfo);
		Address vmtClassName = readPointer(address.add(pointerSize * 8));
		deleteCreateData(vmtClassName, StringDT);
	}

	private List<Address> getChildren(Address parent) {
		List<Address> children = new ArrayList<>();
		for (Relocation reloc : relocations) {
			Address relocAddr = reloc.getAddress();
			if (parent.equals(readPointer(relocAddr))) {
				Address child = relocAddr.subtract(40);
				if (TVmt.isValid(child, relocations, program)) {
					children.add(child);
					putVirtualMethodTable(child);
					createLabel(child, "VMT_" + TVmt.getVMTTypeName(child, program));
				}
			}
		}
		return children;
	}

	// Returns Vmt for TObject which is a starting point for searching all other classes
	private Address getTObjectVmt() throws CancelledException {
		Address typeInfoAddress = getTObjectTypeInfo();
		if (typeInfoAddress == null) return null;
		int pointerSize = typeInfoAddress.getAddressSpace().getPointerSize();

		ArrayList<Byte> bytesList = new ArrayList<Byte>();
		Collections.addAll(bytesList, ArrayUtils.toObject(new byte[pointerSize]));
		Collections.addAll(bytesList, ArrayUtils.toObject(new byte[pointerSize]));
		Collections.addAll(bytesList, ArrayUtils.toObject(new byte[pointerSize]));
		Collections.addAll(bytesList, ArrayUtils.toObject(new byte[pointerSize]));
		Collections.addAll(bytesList, ArrayUtils.toObject(getBytes(typeInfoAddress)));
		Collections.addAll(bytesList, ArrayUtils.toObject(new byte[pointerSize]));
		byte[] bytes = ArrayUtils.toPrimitive(bytesList.toArray(Byte[]::new));

		byte[] filledMask = new byte[pointerSize];
		Arrays.fill(filledMask, (byte) -1);
		ArrayList<Byte> maskList = new ArrayList<Byte>();
		Collections.addAll(maskList, ArrayUtils.toObject(new byte[pointerSize]));
		Collections.addAll(maskList, ArrayUtils.toObject(filledMask));
		Collections.addAll(maskList, ArrayUtils.toObject(filledMask));
		Collections.addAll(maskList, ArrayUtils.toObject(filledMask));
		Collections.addAll(maskList, ArrayUtils.toObject(filledMask));
		Collections.addAll(maskList, ArrayUtils.toObject(filledMask));
		byte[] mask = ArrayUtils.toPrimitive(maskList.toArray(Byte[]::new));

		List<Address> found = findMatches(bytes, mask, "vmtTObject", TTypeInfoDT);
		if (found == null) {
			log.appendMsg("Coudn't find any match for VMT of TObject");
			return null;
		}
		if (found.size() > 1) {
			log.appendMsg("There must be exactly 1 match for VMT of TObject");
			return null;
		}
		return found.get(0);
	}

	private Address getTObjectTypeInfo() throws CancelledException {
		byte[] bytes = {7, 7, 'T', 'O', 'b', 'j', 'e', 'c', 't'};
		String searchName = "\\x07\\x07TObject";
		List<Address> found = findMatches(bytes, searchName, TTypeInfoDT);
		if (found == null) {
			log.appendMsg("Coudn't find any match for TObject type info");
			return null;
		}
		if (found.size() > 1) {
			log.appendMsg("There must be exactly 1 match for TObject type info (class kind + \"TObject\" pascal string)");
			return null;
		}
		Address result = found.get(0);
		putTTypeInfo(result);
		return result;
	}

	private Data deleteCreateData(Address address, DataType dataType) {
		if (address == null) return null;
		if (address.getOffset() == 0) return null;
		Data data = listing.getDataAt(address);
		if (dataType == null) {
			if (data != null) {
				listing.clearCodeUnits(address, address, false);
			}
			return null;
		}
		if (data != null) {
			if (data.getDataType().equals(dataType)) return data;
			if (data.getDataType().isEquivalent(dataType)) return data;
		}
		Address clearAddr = address;
		while (true) {
			try {
				data = listing.createData(address, dataType);
				return data; // No further clearing is required so return immediately
			}
			catch (CodeUnitInsertionException e) {}
			data = listing.getDataAt(clearAddr);
			if (data.isDefined()) { // May encounter no data at this position so a check is required
				listing.clearCodeUnits(clearAddr, clearAddr, false);
			}
			clearAddr = clearAddr.add(1); // Displace clearing address 1 byte forward and make a next try
		}
	}

	private void createLabel(Address address, String name) {
		try {
			Symbol symbol = symbolTable.getPrimarySymbol(address);
			if (symbol != null) {
				if (symbol.getName().equals(name)) {
					if (symbol.getSource() == SourceType.ANALYSIS) {
						return;
					}
				}
			}
			symbolTable.createLabel(address, name, SourceType.ANALYSIS);
		} catch (InvalidInputException e) {}
	}

	private byte[] getBytes(Address address) {
		int pointerSize = address.getAddressSpace().getPointerSize();
		return Utils.longToBytes(address.getOffset(), pointerSize, bigEndian);
	}

	private byte[] readBytes(Address address, int size) throws MemoryAccessException {
		byte[] bytes = new byte[size];
		memory.getBytes(address, bytes);
		return bytes;
	}

	private long readNumber(Address address, int size) throws MemoryAccessException {
		byte[] bytes = readBytes(address, size);
		return Utils.bytesToLong(bytes, size, bigEndian);
	}

	private Address readPointer(Address address) {
		if (address == null) return null;
		int size = address.getPointerSize();
		try {
			long offset = readNumber(address, size);
			if (offset == 0) return null; // Assume null pointer is not mapped to any valid data
			AddressSpace space = address.getAddressSpace();
			return space.getAddress(offset); // Assume address space is the same
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			return null;
		}
	}

	private String readCString(Address address) {
		if (address == null) return null;
		try {
			StringBuilder str = new StringBuilder();
			while (readNumber(address, 1) != 0) {
				char c = (char) readNumber(address, 1);
				address = address.add(1);
				str.append(c);
			}
			return str.toString();
		} catch (MemoryAccessException | NullPointerException e) {
			return null;
		}
	}

	private List<Address> findMatches(byte[] bytes, String searchName, DataType dataType) throws CancelledException {
		MemoryBytePatternSearcher searcher = new MemoryBytePatternSearcher(searchName);
		List<Address> found = new ArrayList<>();
		GenericMatchAction<DataType> action = new GenericMatchAction<DataType>(dataType) {
			@Override
			public void apply(Program prog, Address addr, Match match) {
				found.add(addr);
			}
		};
		GenericByteSequencePattern<DataType> pattern = new GenericByteSequencePattern<DataType>(bytes, action);
		searcher.addPattern(pattern);
		searcher.search(program, set, monitor);
		if (found.isEmpty()) return null;
		return found;
	}

	private List<Address> findMatches(byte[] bytes, byte[] mask, String searchName, DataType dataType) throws CancelledException {
		MemoryBytePatternSearcher searcher = new MemoryBytePatternSearcher(searchName);
		List<Address> found = new ArrayList<>();
		GenericMatchAction<DataType> action = new GenericMatchAction<DataType>(dataType) {
			@Override
			public void apply(Program prog, Address addr, Match match) {
				found.add(addr);
			}
		};
		GenericByteSequencePattern<DataType> pattern = new GenericByteSequencePattern<DataType>(bytes, mask, action);
		searcher.addPattern(pattern);
		searcher.search(program, set, monitor);
		if (found.isEmpty()) return null;
		return found;
	}
}

package ghidra.app.plugin.prototype;

import ghidra.app.cmd.data.rtti.borland.delphi.datatype.*;
import ghidra.app.cmd.data.rtti.borland.delphi.util.*;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.symbol.*;
import ghidra.util.InvalidNameException;
import ghidra.util.bytesearch.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import org.apache.commons.lang3.ArrayUtils;

import java.lang.Byte;
import java.util.*;

public class BorlandDelphiRttiAnalyzer extends AbstractAnalyzer {

	private static final String ANALYZER_NAME = "Borland Delphi RTTI Analyzer";
	private static final String DESCRIPTION =
		"This analyzer finds and creates all of the RTTI metadata structures and their associated vtables.";
	private Program program;
	private AddressSetView set;
	private TaskMonitor monitor;
	private MessageLog log;
	private Memory memory;
	private boolean bigEndian;
	private ProgramBasedDataTypeManager dataTypeManager;
	private CategoryPath systemPath;
	private StructureDataType TTypeInfoDT;
	private PascalString255DataType StringDT;
	private PointerDataType PointerDT;
	private StructureDataType TVmtDT;
	private long TVmtSize;
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
		Address selfPtr = MemoryUtil.readPointer(vmtAddress, program);
		if (selfPtr == null) return false;
		TVmtSize = selfPtr.subtract(vmtAddress);
		TVmtDT = TVmt.getDataType(TVmtSize, systemPath, dataTypeManager);
		TVmt.putObject(vmtAddress, TVmtSize, systemPath, program);
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

		memory = program.getMemory();
		bigEndian = program.getLanguage().isBigEndian();
		dataTypeManager = program.getDataTypeManager();
		try {
			systemPath = dataTypeManager.getCategory(CategoryPath.ROOT).createCategory("system.pas").getCategoryPath();
		} catch (InvalidNameException e) {
			return false;
		}
		StringDT = PascalString255DataType.dataType;
		/*String compilerVersion = getCompilerVersion();
		if (compilerVersion == null) {
			return false;
		}*/

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
		String string = MemoryUtil.readCString(address, program);
		if (string == null) return null;
		String searchString = "compiler version";
		if (!string.contains(searchString)) return null;
		String versionString = string.substring(string.indexOf(searchString) + searchString.length());
		if (!versionString.contains("(")) return null;
		versionString = versionString.substring(0, versionString.indexOf("("));
		versionString = versionString.replace(" ", ""); // Delete extra space chars
		Data data = ListingUtils.deleteCreateData(address, TerminatedStringDataType.dataType, program);
		return versionString;
	}

	private List<Address> getChildren(Address parent) {
		List<Address> children = new ArrayList<>();
		for (Relocation reloc : relocations) {
			Address relocAddr = reloc.getAddress();
			if (parent.equals(MemoryUtil.readPointer(relocAddr, program))) {
				Address child = relocAddr.subtract(40);
				if (TVmt.isValid(child, TVmtSize, relocations, program)) {
					children.add(child);
					TVmt.putObject(child, TVmtSize, systemPath, program);
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
		TTypeInfo.putObject(result, systemPath, program);
		return result;
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

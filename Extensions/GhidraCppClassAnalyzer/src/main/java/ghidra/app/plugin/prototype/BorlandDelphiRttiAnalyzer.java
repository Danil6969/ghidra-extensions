package ghidra.app.plugin.prototype;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.InvalidNameException;
import ghidra.util.bytesearch.GenericByteSequencePattern;
import ghidra.util.bytesearch.GenericMatchAction;
import ghidra.util.bytesearch.Match;
import ghidra.util.bytesearch.MemoryBytePatternSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import org.apache.commons.lang3.ArrayUtils;

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
	private StructureDataType TTypeInfo;
	private PascalString255DataType StringDT;
	private PointerDataType PointerDT;
	private StructureDataType TVmtDT;
	RelocationTable relocationTable;
	List<Address> relocations;
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
		TVmtDT = getTVmtDataType(diff);
		putVirtualMethodTable(vmtAddress);
		pending.add(vmtAddress);
		while (!pending.isEmpty()) {
			Address parent = pending.remove(0);
			if (ready.contains(parent)) continue;
			getChildren(parent);
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

		TTypeKindDT = getTTypeKindDataType();
		TTypeInfo = getTTypeInfoDataType();
		StringDT = PascalString255DataType.dataType;
		PointerDT = PointerDataType.dataType;

		relocationTable = program.getRelocationTable();
		Iterator<Relocation> iterator = relocationTable.getRelocations();
		relocations = new ArrayList<>();
		while (iterator.hasNext()) {
			Relocation relocation = iterator.next();
			Address relAddr = relocation.getAddress();
			relocations.add(relAddr);
		}
		ready = new LinkedList<>();
		pending = new LinkedList<>();
		return true;
	}

	private EnumDataType getTTypeKindDataType() {
		EnumDataType TTypeKindDT = new EnumDataType(systemPath, "TTypeKind", 1, dataTypeManager);
		TTypeKindDT.add("tkUnknown", 0);
		TTypeKindDT.add("tkInteger", 1);
		TTypeKindDT.add("tkChar", 2);
		TTypeKindDT.add("tkEnumeration", 3);
		TTypeKindDT.add("tkFloat", 4);
		TTypeKindDT.add("tkString", 5);
		TTypeKindDT.add("tkSet", 6);
		TTypeKindDT.add("tkClass", 7);
		TTypeKindDT.add("tkMethod", 8);
		TTypeKindDT.add("tkWChar", 9);
		TTypeKindDT.add("tkLString", 10);
		TTypeKindDT.add("tkWString", 11);
		TTypeKindDT.add("tkVariant", 12);
		TTypeKindDT.add("tkArray", 13);
		TTypeKindDT.add("tkRecord", 14);
		TTypeKindDT.add("tkInterface", 15);
		TTypeKindDT.add("tkInt64", 16);
		TTypeKindDT.add("tkDynArray", 17);
		TTypeKindDT.add("tkUString", 18);
		TTypeKindDT.add("tkClassRef", 19);
		TTypeKindDT.add("tkPointer", 20);
		TTypeKindDT.add("tkProcedure", 21);
		return TTypeKindDT;
	}

	private StructureDataType getTTypeInfoDataType() {
		StructureDataType TTypeInfoDT = new StructureDataType(systemPath, "TTypeInfo", 0, dataTypeManager);
		TTypeInfoDT.add(TTypeKindDT);
		TTypeInfoDT.add(new ArrayDataType(CharDataType.dataType, 0, -1));
		return TTypeInfoDT;
	}

	private void putTTypeInfo(Address address) {
		deleteCreateData(address, TTypeInfo);
		deleteCreateData(address.add(TTypeInfo.getLength()), PascalString255DataType.dataType);
	}

	private StructureDataType getTVmtDataType(long maxLength) {
		int pointerSize = PointerDT.getLength();
		StructureDataType VirtualMethodTableDT = new StructureDataType(systemPath, "TVmt", 0, dataTypeManager);
		VirtualMethodTableDT.add(PointerDT, "SelfPtr", "Pointer to self");
		VirtualMethodTableDT.add(PointerDT, "IntfTable", "Pointer to interface table");
		VirtualMethodTableDT.add(PointerDT, "AutoTable", "Pointer to automation initialization");
		VirtualMethodTableDT.add(PointerDT, "InitTable", "Pointer to object initialization");
		VirtualMethodTableDT.add(new PointerDataType(TTypeInfo), "TypeInfo", "Pointer to type information table");
		VirtualMethodTableDT.add(PointerDT, "FieldTable", "Pointer to field definition table");
		VirtualMethodTableDT.add(PointerDT, "MethodTable", "Pointer to method definition table");
		VirtualMethodTableDT.add(PointerDT, "DynamicTable", "Pointer to dynamic method table");
		VirtualMethodTableDT.add(new PointerDataType(StringDT), "ClassName", "Class name pointer");
		VirtualMethodTableDT.add(AbstractIntegerDataType.getSignedDataType(pointerSize, dataTypeManager), "InstanceSize", "Instance size");
		VirtualMethodTableDT.add(PointerDT, "Parent", "Pointer to parent class");
		while (VirtualMethodTableDT.getLength() < maxLength - (maxLength % pointerSize)) {
			VirtualMethodTableDT.add(PointerDT);
		}
		while (VirtualMethodTableDT.getLength() < maxLength) {
			VirtualMethodTableDT.add(Undefined.getUndefinedDataType(1));
		}
		return VirtualMethodTableDT;
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
		return null;
	}

	private boolean isValidVMT(Address address) {
		return true;
	}

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

		List<Address> found = findMatches(bytes, mask, "vmtTObject", TTypeInfo);
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
		List<Address> found = findMatches(bytes, searchName, TTypeInfo);
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
		if (data != null && data.getDataType().equals(dataType)) return data;
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

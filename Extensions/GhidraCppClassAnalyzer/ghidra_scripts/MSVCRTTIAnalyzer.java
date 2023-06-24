//@category CppClassAnalyzer

import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.service.ClassTypeInfoManagerService;
import cppclassanalyzer.service.RttiManagerProvider;
import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.rtti.*;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import mdemangler.*;

import java.math.BigInteger;
import java.util.*;

public class MSVCRTTIAnalyzer extends GhidraScript {
	private DataType typeDescriptorDT;
	private DataType baseClassDescriptorDT;
	private DataType classHierarchyDescriptorDT;
	private DataType completeObjectLocatorDT;
	private Listing listing;
	private Memory memory;
	private RelocationTable relocationTable;
	private Language language;
	private boolean bigEndian;
	private ProgramBasedDataTypeManager dataTypeManager;
	private SymbolTable symbolTable;
	private MDMangGhidra demangler;
	private CategoryPath path;
	private final List<Address> relocations = new ArrayList<>();
	private final List<Data> typeDescriptors = new ArrayList<>();
	private final List<Data> classHierarchyDescriptors = new ArrayList<>();
	private final List<Data> completeObjectLocators = new ArrayList<>();
	private final List<Address> vftables = new ArrayList<>();

	@Override
	public void run() throws Exception {
		init();
		populateTypeDescriptors();
		populateCompleteObjectLocators();
		populateBaseClassDescriptors();
		populateVFTables();
	}

	private void init() {
		listing = currentProgram.getListing();
		memory = currentProgram.getMemory();
		relocationTable = currentProgram.getRelocationTable();
		language = currentProgram.getLanguage();
		bigEndian = language.isBigEndian();
		dataTypeManager = currentProgram.getDataTypeManager();
		symbolTable = currentProgram.getSymbolTable();
		demangler = new MDMangGhidra();

		// Path for datatypes
		path = CategoryPath.ROOT;

		// Datatypes
		typeDescriptorDT = TypeDescriptorModel.getDataType(currentProgram);
		baseClassDescriptorDT = Rtti1Model.getDataType(currentProgram);
		classHierarchyDescriptorDT = Rtti3Model.getDataType(currentProgram);
		completeObjectLocatorDT = Rtti4Model.getDataType(currentProgram);

		// Relocation addresses
		Iterator<Relocation> iterator = relocationTable.getRelocations();
		while (iterator.hasNext()) {
			Relocation relocation = iterator.next();
			Address relAddr = relocation.getAddress();
			relocations.add(relAddr);
		}
	}

	private void populateTypeDescriptors() throws Exception {
		for (Address relAddr : relocations) { // Pointer to "TypeDescriptor" instance
			int pointerSize = relAddr.getAddressSpace().getPointerSize();
			Address tagAddr = relAddr.add(packedOffset(pointerSize) * 2); // Pointer to "name" field
			byte[] bytes = readBytes(tagAddr, 3);
			boolean tagMatches = true;
			tagMatches &= bytes[0] == '.'; // 0x2e
			tagMatches &= bytes[1] == '?'; // 0x3f
			tagMatches &= bytes[2] == 'A'; // 0x41
			if (tagMatches) { // Tag must be ".?A"
				String mangled = readString(TerminatedStringDataType.dataType, tagAddr);
				String type = getSymbolType(mangled);
				String name = getNamespaceName(mangled);
				if (type == null || name == null) {
					continue;
				}
				addSymbol(type, name);
				Data data = deleteCreateData(relAddr, typeDescriptorDT);
				typeDescriptors.add(data);
				name += "::`TypeDescriptor'";
				createLabel(relAddr, name);
				deleteCreateData(tagAddr, TerminatedStringDataType.dataType);
			}
		}
	}

	private void populateCompleteObjectLocators() throws Exception {
		for (Address relAddr : relocations) { // Vftable meta pointer
			try {
				int pointerSize = relAddr.getAddressSpace().getPointerSize();
				Address COLAddr = readPointer(relAddr); // Pointer to "RTTICompleteObjectLocator" instance
				Address pTDAddr = COLAddr.add(4 * 3); // Pointer to "pTypeDescriptor" field
				if (getDataFromPointer(pTDAddr, typeDescriptors) == null) continue;
				Address pCDAddr = pTDAddr.add(packedOffset(pointerSize)); // Pointer to "pClassDescriptor" field
				Address CHDAddr = readPointer(pCDAddr); // Pointer to "RTTIClassHierarchyDescriptor" instance
				readNumber(CHDAddr, 1);
				deleteCreateData(relAddr, new PointerDataType(completeObjectLocatorDT));
				Data data = deleteCreateData(COLAddr, completeObjectLocatorDT);
				completeObjectLocators.add(data);
				data = deleteCreateData(CHDAddr, classHierarchyDescriptorDT);
				classHierarchyDescriptors.add(data);
				data = getDataFromPointer(pTDAddr, typeDescriptors);
				data = listing.getDataAt(data.getMaxAddress().add(1));
				deleteCreateData(data.getAddress(), TerminatedStringDataType.dataType);
				String mangled = readString(TerminatedStringDataType.dataType, data.getAddress());
				String name = getNamespaceName(mangled);
				name += "::`RTTICompleteObjectLocator'";
				createLabel(COLAddr, name);
				name = getNamespaceName(mangled);
				name += "::`RTTIClassHierarchyDescriptor'";
				createLabel(CHDAddr, name);
				// Also add to vftables list
				Address elemAddr = relAddr.add(pointerSize);
				Address codeAddr = readPointer(elemAddr);
				if (codeAddr != null && listing.getCodeUnitAt(codeAddr) instanceof Instruction) {
					vftables.add(elemAddr);
				}
			}
			catch (MemoryAccessException | AddressOutOfBoundsException e) {}
		}
	}

	private void populateBaseClassDescriptors() throws Exception {
		for (Data completeObjectLocator : completeObjectLocators) {
			Address COLAddr = completeObjectLocator.getAddress(); // Pointer to "RTTICompleteObjectLocator" instance
			int pointerSize = COLAddr.getAddressSpace().getPointerSize();
			Address pTDAddr = COLAddr.add(4 * 3); // Pointer to "pTypeDescriptor" field
			Address pCDAddr = pTDAddr.add(packedOffset(pointerSize));  // Pointer to "pClassDescriptor" field
			Address CHDAddr = readPointer(pCDAddr); // Pointer to "RTTIClassHierarchyDescriptor" instance
			Address pBCAAddr = CHDAddr.add(4 * 3); // Pointer to "pBaseClassArray" field
			int count = 0;
			Address BCAAddr = readPointer(pBCAAddr);
			Address TDAddr = readPointer(pTDAddr); // Pointer to "TypeDescriptor" instance
			Address nameAddr = TDAddr.add(packedOffset(pointerSize) * 2); // Pointer to "name" field
			String mangled = readString(TerminatedStringDataType.dataType, nameAddr);
			String name = getNamespaceName(mangled);
			name += "::`RTTIBaseClassArray'";
			createLabel(BCAAddr, name);
			for (Address elemAddr = BCAAddr; readNumber(elemAddr, pointerSize) != 0; elemAddr = elemAddr.add(packedOffset(pointerSize))) {
				Address BCDAddr = readPointer(elemAddr); // Pointer to "RTTIBaseClassDescriptor" instance
				deleteCreateData(BCDAddr, baseClassDescriptorDT);
				Address baseTDAddr = readPointer(BCDAddr); // Pointer to "TypeDescriptor" instance (base class)
				Address baseNameAddr = baseTDAddr.add(packedOffset(pointerSize) * 2); // Pointer to "name" field
				mangled = readString(TerminatedStringDataType.dataType, baseNameAddr);
				name = getNamespaceName(mangled);
				name += "::`RTTIBaseClassDescriptorAt(";
				Address PMDAddr = BCDAddr.add(packedOffset(pointerSize)).add(4);
				name += readNumber(PMDAddr, 4, true) + ",";
				name += readNumber(PMDAddr.add(4), 4, true) + ",";
				name += readNumber(PMDAddr.add(8), 4, true) + ",";
				name += readNumber(PMDAddr.add(12), 4, true) + ")'";
				createLabel(BCDAddr, name);
				count++;
			}
			deleteCreateData(BCAAddr, new ArrayDataType(new PointerDataType(baseClassDescriptorDT), count, -1));
		}
	}

	private void populateVFTables() throws Exception {
		for (Address vftable : vftables) {
			int pointerSize = vftable.getAddressSpace().getPointerSize();
			Address COLAddr = readPointer(vftable.subtract(pointerSize)); // Pointer to "RTTICompleteObjectLocator" instance
			Address pTDAddr = COLAddr.add(4 * 3); // Pointer to "pTypeDescriptor" field
			Address TDAddr = readPointer(pTDAddr); // Pointer to "TypeDescriptor" instance
			Address nameAddr = TDAddr.add(packedOffset(pointerSize) * 2); // Pointer to "name" field
			String mangled = readString(TerminatedStringDataType.dataType, nameAddr);
			String name = getNamespaceName(mangled);
			Address elemAddr = vftable;
			while (containsPointer(elemAddr)) {
				if (getDataFromPointer(elemAddr, completeObjectLocators) != null) {
					break;
				}
				Address codeAddr = readPointer(elemAddr);
				Function function = listing.getFunctionAt(codeAddr);
				if (function == null) {
					if (!(listing.getCodeUnitAt(codeAddr) instanceof Instruction)) {
						deleteCreateData(codeAddr, null);
					}
					CreateFunctionCmd cmd = new CreateFunctionCmd(codeAddr);
					cmd.applyTo(currentProgram);
					function = listing.getFunctionAt(codeAddr);
				}
				Data data = listing.getDataAt(elemAddr);
				if (data == null) {
					deleteCreateData(elemAddr, new PointerDataType());
				}
				else {
					String dtname = data.getDataType().getName();
					if (dtname.startsWith("undefined") && !dtname.equals("undefined *")) {
						deleteCreateData(elemAddr, new PointerDataType());
					}
				}
				elemAddr = elemAddr.add(pointerSize);
			}
		}
	}

	private boolean containsPointer(Address address) {
		try {
			Address pointedAddr = readPointer(address);
			if (pointedAddr == null) return false;
			if (listing.getCodeUnitAt(pointedAddr) instanceof Instruction) return true;
			if (relocations.contains(address)) return true;
			return false;
		} catch (Exception e) {
			return false;
		}
	}

	private long packedOffset(long size) {
		long pack = 4;
		if (size < pack) return 4;
		return size;
	}

	private void createLabel(Address address, String name) throws InvalidInputException {
		Data data = listing.getDataAt(address);
		if (data == null) {
			symbolTable.createLabel(address, name, SourceType.ANALYSIS);
			return;
		}
		String label = data.getLabel();
		if (label == null) {
			symbolTable.createLabel(address, name, SourceType.ANALYSIS);
			return;
		}
		String defaultLabel = data.getDefaultLabelPrefix(null) + '_';
		defaultLabel += address.getAddressSpace().getName() + '_';
		defaultLabel += address.getOffsetAsBigInteger().toString(16);
		if (label.equals(name)) {
			return;
		}
		if (!label.equals(defaultLabel)) {
			println("Custom label at " + address + " is already defined, skipped");
			return;
		}
		symbolTable.createLabel(address, name, SourceType.ANALYSIS);
	}

	// Deletes and creates data with non-null datatype. If datatype is null just clears data
	private Data deleteCreateData(Address address, DataType dataType) {
		Data data = listing.getDataAt(address);
		if (dataType == null) {
			if (data != null) {
				listing.clearCodeUnits(address, address, false);
			}
			return null;
		}
		if (data != null && data.getDataType().isEquivalent(dataType)) return data;
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

	// Reads string at address using specified datatype algorithm
	private String readString(DataType dt, Address address) {
		MemoryBufferImpl buf = new MemoryBufferImpl(memory, address);
		StringDataInstance string = new StringDataInstance(dt, dt.getDefaultSettings(), buf, -1);
		int length = string.getStringLength();
		string = new StringDataInstance(dt, dt.getDefaultSettings(), buf, length);
		return string.getStringValue();
	}

	// Adds RTTI symbol to class and datatype databases
	private void addSymbol(String type, String name) throws Exception {
		if (type.equals("class")) {
			Namespace global = currentProgram.getGlobalNamespace();
			try {
				symbolTable.createClass(global, name, SourceType.ANALYSIS);
			}
			catch (DuplicateNameException e) {}
			if (dataTypeManager.getDataType(path, name) == null) {
				dataTypeManager.addDataType(newStruct(name), DataTypeConflictHandler.DEFAULT_HANDLER);
			}
		}
		else if (type.equals("struct")) {
			if (dataTypeManager.getDataType(path, name) == null) {
				dataTypeManager.addDataType(newStruct(name), DataTypeConflictHandler.DEFAULT_HANDLER);
			}
		}
		else {
			printerr("Unimplemented symbol type: " + type);
		}
	}

	private String getSymbolType(String mangled) {
		mangled = mangled.substring(0, mangled.length() - 1);
		try {
			MDParsableItem demangItem = demangler.demangle(mangled, false);
			if (demangItem == null) return null;
			String demangled = demangItem.toString();
			int spacePos = demangled.indexOf(' ');
			return demangled.substring(0, spacePos);
		} catch (Exception e) {
			return null;
		}
	}

	private String getNamespaceName(String mangled) {
		mangled = mangled.substring(0, mangled.length() - 1);
		try {
			demangler.demangle(mangled, false);
			return demangler.getDataType().getNamespaceName();
		}
		catch (Exception e) {
			return null;
		}
	}

	private StructureDataType newStruct(String structureName) {
		return new StructureDataType(path, structureName, 0, dataTypeManager);
	}

	private byte[] readBytes(Address address, int size) throws MemoryAccessException {
		byte[] bytes = new byte[size];
		memory.getBytes(address, bytes);
		return bytes;
	}

	private BigInteger readNumber(Address address, int size, boolean signed) throws MemoryAccessException {
		byte[] bytes = readBytes(address, size);
		return Utils.bytesToBigInteger(bytes, size, bigEndian, signed);
	}

	private long readNumber(Address address, int size) throws MemoryAccessException {
		byte[] bytes = readBytes(address, size);
		return Utils.bytesToLong(bytes, size, bigEndian);
	}

	private Address readPointer(Address address) throws Exception {
		if (address == null) return null;
		int size = address.getPointerSize();
		try {
			long offset = readNumber(address, size);
			AddressSpace space = address.getAddressSpace();
			return space.getAddress(offset); // Assume address space is the same
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			return null;
		}
	}

	// Reads pointer on address and returns first data if found in list
	private Data getDataFromPointer(Address address, List<Data> dataList) throws Exception {
		if (address == null) return null;
		Address pointer = readPointer(address);
		for (Data data : dataList) {
			Address dataAddr = data.getAddress();
			if (dataAddr.equals(pointer))
				return data;
		}
		return null;
	}
}

package ghidra.app.cmd.data.rtti.gcc;

import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.data.typeinfo.GnuClassTypeInfoDB;
import cppclassanalyzer.data.typeinfo.AbstractClassTypeInfoDB.TypeId;
import cppclassanalyzer.utils.CppClassAnalyzerUtils;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.docking.settings.Settings;
import ghidra.util.InvalidNameException;
import util.CollectionUtils;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.GnuVtable;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.BaseClassTypeInfoModel;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.VmiClassTypeInfoModel;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.SpecialAddress;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

import static ghidra.app.cmd.data.rtti.GnuVtable.PURE_VIRTUAL_FUNCTION_NAME;

public class ClassTypeInfoUtils {
	public enum VtableMode {
		VS, GCC;
	}

	private static final String PLACEHOLDER_DESCRIPTION = "PlaceHolder Class Structure";
	private static final String MISSING = "Missing";

	private ClassTypeInfoUtils() {
	}

	/**
	 * Finds the Vtable for the corresponding TypeInfo
	 *
	 * @param program the program to be searched
	 * @param address the address of the TypeInfo Model's DataType
	 * @param monitor the taskmonitor to be used while searching for the vtable
	 * @return The TypeInfo's Vtable Model or null if none exists
	 * @throws CancelledException if the search is cancelled
	 */
	public static Vtable findVtable(Program program, Address address, TaskMonitor monitor)
		throws CancelledException {
			ProgramClassTypeInfoManager manager = CppClassAnalyzerUtils.getManager(program);
			ClassTypeInfo type = manager.getType(address);
			if (type != null) {
				return findVtable(program, type, monitor);
			}
			return Vtable.NO_VTABLE;
	}

	/**
	 * Finds the Vtable for the corresponding TypeInfo
	 *
	 * @param program the program to be searched
	 * @param type the typeinfo to find the vtable for
	 * @param monitor the taskmonitor to be used while searching for the vtable
	 * @return The TypeInfo's Vtable Model or null if none exists
	 * @throws CancelledException if the search is cancelled
	 */
	public static Vtable findVtable(Program program, ClassTypeInfo type, TaskMonitor monitor)
		throws CancelledException {
			SymbolTable table = program.getSymbolTable();
			Listing listing = program.getListing();
			List<Symbol> symbols =
				table.getSymbols(VtableModel.SYMBOL_NAME, type.getNamespace());
			for (Symbol symbol : symbols) {
				try {
					return new VtableModel(program, symbol.getAddress(), type);
				} catch (InvalidDataTypeException e) {
					break;
				}
			}
			Set<Address> references = Collections.emptySet();
			Data tiData = listing.getDataAt(type.getAddress());
			if (tiData != null) {
				references = CollectionUtils.asStream(tiData.getReferenceIteratorTo())
					.map(Reference::getFromAddress)
					.filter(Predicate.not(SpecialAddress.class::isInstance))
					.collect(Collectors.toSet());
				if (!references.isEmpty()) {
					Vtable vtable = getValidVtable(program, references, monitor, type);
					if (Vtable.isValid(vtable)) {
						return vtable;
					}
				}
			}
			if (type.getName().contains("type_info")) {
				references = GnuUtils.getDirectDataReferences(program, type.getAddress());
				if (!references.isEmpty()) {
					Vtable vtable = getValidVtable(program, references, monitor, type);
					if (Vtable.isValid(vtable)) {
						return vtable;
					}
				}
			}
			return Vtable.NO_VTABLE;
	}

	private static boolean invalidData(Data data) {
		if (data == null) {
			return false;
		}
		DataType dataType = data.getDataType();
		if (dataType instanceof Pointer) {
			return false;
		}
		if (dataType instanceof DefaultDataType) {
			return false;
		}
		if (Undefined.isUndefinedArray(dataType)) {
			return false;
		}
		return true;
	}

	private static Vtable getValidVtable(Program program, Set<Address> references,
		TaskMonitor monitor, ClassTypeInfo typeinfo) throws CancelledException {
		Listing listing = program.getListing();
		Memory mem = program.getMemory();
		DataType ptrDiff = GnuUtils.getPtrDiff_t(program.getDataTypeManager());
		Scalar zero = new Scalar(ptrDiff.getLength(), 0);
		boolean hasPureVirtual = program.getSymbolTable().getSymbols(
			PURE_VIRTUAL_FUNCTION_NAME).hasNext();
		for (Address reference : references) {
			monitor.checkCanceled();
			MemBuffer buf = new DumbMemBufferImpl(mem, reference.subtract(ptrDiff.getLength()));
			Object value = ptrDiff.getValue(
				buf, ptrDiff.getDefaultSettings(), ptrDiff.getLength());
			if(!zero.equals(value)) {
				continue;
			}
			Data data = listing.getDataContaining(reference);
			if (invalidData(data)) {
				continue;
			}
			try {
				final VtableModel vtable = new VtableModel(program, reference, typeinfo);
				final Function[][] functionTables = vtable.getFunctionTables();
				if (functionTables.length > 0) {
					if (functionTables[0].length > 0) {
						if (functionTables[0][0] == null) {
							for (Function function : functionTables[0]) {
								if (function == null) {
									continue;
								} if (hasPureVirtual) {
									if (PURE_VIRTUAL_FUNCTION_NAME.equals(function.getName())) {
										return vtable;
									}
								} else {
									return vtable;
								}
							}
							// construction vtable
							continue;
						}
					}
				}
				return vtable;
			} catch (InvalidDataTypeException e) {
				continue;
			}
		}
		return VtableModel.NO_VTABLE;
	}

	/**
	 * Gets the placeholder struct for a ClassTypeInfo in a specified DataTypeManager
	 * @param type the ClassTypeInfo
	 * @param dtm the DataTypeManager
	 * @return the placeholder struct for a ClassTypeInfo in a specified DataTypeManager
	 */
	public static Structure getPlaceholderStruct(ClassTypeInfo type, DataTypeManager dtm) {
		ProgramClassTypeInfoManager manager =
			CppClassAnalyzerUtils.getManager(type.getGhidraClass().getSymbol().getProgram());
		DataType thiscallStruct =
			VariableUtilities.findOrCreateClassStruct(type.getGhidraClass(), dtm);
		ClassTypeInfo otherType = manager.getType(thiscallStruct.getUniversalID());
		if (otherType != null && !otherType.equals(type)) {
			return getFixedIncorrectStructure(type, dtm);
		}
		CategoryPath path = TypeInfoUtils.getCategoryPath(type);
		CategoryPath otherPath = thiscallStruct.getCategoryPath();
		if (!path.isRoot() && !otherPath.isRoot()) {
			if (path.equals(otherPath)) {
				return (Structure) thiscallStruct;
			}
		}
		Namespace ns = type.getNamespace().getParentNamespace();
		if (ns != null && !ns.isGlobal() && ns.getName(true).equals(path.getName())) {
			// assume VariableUtilities found the type from debug info
			return (Structure) thiscallStruct;
		}
		if (path.isRoot() && !otherPath.isRoot()) {
			// assume VariableUtilities found the type from debug info
			return (Structure) thiscallStruct;
		}
		return getFixedIncorrectStructure(type, dtm);
	}

	private static Structure getFixedIncorrectStructure(ClassTypeInfo type, DataTypeManager dtm) {
		String msg = "Variable Utils returned wrong class structure! " + type.getName();
		Msg.warn(ClassTypeInfoUtils.class, msg);
		int id = dtm.startTransaction("getting placeholder struct for "+type.getName());
		boolean success = false;
		try {
			CategoryPath path = TypeInfoUtils.getDataTypePath(type).getCategoryPath();
			DataType struct = dtm.getDataType(path, type.getName());
			if (struct == null) {
				struct = new StructureDataType(path, type.getName(), 0, dtm);
				struct = dtm.resolve(struct, DataTypeConflictHandler.KEEP_HANDLER);
			}
			success = true;
			return (Structure) struct;
		} finally {
			dtm.endTransaction(id, success);
		}
	}

	/**
	 * Returns true if the Structure is a "placeholder" structure.
	 *
	 * @param struct the Structure to check.
	 * @return true if the Structure is a "placeholder" structure.
	 */
	public static boolean isPlaceholder(Structure struct) {
		if (struct == null) {
			return true;
		}
		String description = struct.getDescription();
		return description.equals(PLACEHOLDER_DESCRIPTION) || description.startsWith(MISSING);
	}

	/**
	 * Gets the function for the ClassTypeInfo at the specified address.
	 *
	 * @param program the Program the function is in.
	 * @param type the ClassTypeInfo for the function.
	 * @param address the Address of the function.
	 * @return the requested ClassTypeInfo's function.
	 */
	public static Function getClassFunction(Program program, ClassTypeInfo type, Address address) {
		Listing listing = program.getListing();
		FunctionManager functionManager = program.getFunctionManager();
		if (listing.getInstructionAt(address) == null) {
			DisassembleCommand cmd = new DisassembleCommand(address, null, true);
			cmd.applyTo(program);
		}
		if (!functionManager.isInFunction(address)) {
			CreateFunctionCmd cmd = new CreateFunctionCmd(address, true);
			if (!cmd.applyTo(program)) {
				return null;
			}
		}
		Function function = functionManager.getFunctionContaining(address);
		if (listing.getInstructionAt(function.getEntryPoint()) == null) {
			DisassembleCommand cmd =
				new DisassembleCommand(function.getEntryPoint(), null, true);
			cmd.applyTo(program);
		}
		try {
			if (function.isThunk()) {
				function = function.getThunkedFunction(true);
			}
			function.setParentNamespace(type.getGhidraClass());
			function.setCallingConvention(GenericCallingConvention.thiscall.getDeclarationName());
			// necessary due to ghidra bug.
			function.setCustomVariableStorage(true);
			function.setCustomVariableStorage(false);
			return function;
		} catch (Exception e) {
			throw new AssertException(String.format(
				"Failed to retrieve class function for %s at %s", type, address), e);
		}
	}

	/**
	 * Sets the provided function to be a class function for the provided type
	 * @param type the class type
	 * @param function the function
	 * @throws IllegalArgumentException if the function is external
	 */
	public static void setClassFunction(ClassTypeInfo type, Function function) {
		Objects.requireNonNull(type);
		Objects.requireNonNull(function);
		if (function.isExternal()) {
			throw new IllegalArgumentException(function.getName(true)+" is an external function");
		}
		Address entry = function.getEntryPoint();
		if (function.getBody().getNumAddresses() <= 1) {
			DisassembleCommand cmd =
				new DisassembleCommand(entry, null, true);
			cmd.applyTo(function.getProgram());
		}
		if (function.isThunk()) {
			function = function.getThunkedFunction(true);
		}
		boolean success = false;
		int id = function.getProgram().startTransaction(
			String.format("Setting class function for %s at %s", type, entry));
		try {
			function.setParentNamespace(type.getGhidraClass());
			function.setCallingConvention(GenericCallingConvention.thiscall.getDeclarationName());
			success = true;
		} catch (Exception e) {
			throw new AssertException(String.format(
				"Failed to retrieve class function for %s at %s", type, entry), e);
		} finally {
			function.getProgram().endTransaction(id, success);
		}
	}

	/**
	 * Sorts a list of classes in order of most derived
	 * @param program the program containing the list of ClassTypeInfo
	 * @param classes the list of ClassTypeInfo
	 * @param monitor the task monitor
	 * @throws CancelledException if the operation is cancelled
	 */
	public static void sortByMostDerived(Program program, List<ClassTypeInfo> classes,
		TaskMonitor monitor) throws CancelledException {
			Set<ClassTypeInfo> classSet = new LinkedHashSet<>(classes);
			List<ClassTypeInfo> sortedClasses = new ArrayList<>(classes.size());
			Iterator<ClassTypeInfo> classIterator = classSet.iterator();
			while (classIterator.hasNext()) {
				monitor.checkCanceled();
				ClassTypeInfo type = classIterator.next();
				ArrayDeque<ClassTypeInfo> stack = new ArrayDeque<>();
				stack.push(type);
				while(!stack.isEmpty()) {
					monitor.checkCanceled();
					ClassTypeInfo classType = stack.pop();
					if (classType.hasParent() && classSet.contains(classType)) {
						ClassTypeInfo parent = classType.getParentModels()[0];
						if (classSet.contains(parent)) {
							stack.push(classType);
							stack.push(parent);
							continue;
						}
					}
					sortedClasses.add(classType);
					classSet.remove(classType);
				} classIterator = classSet.iterator();
			}
			classes.clear();
			classes.addAll(sortedClasses);
	}

	/**
	 * Gets index which corresponds to base (zero offset) function table.
	 * @param program the program containing the vtable
	 * @param vtable the vtable
	 * @param mode determines how the table is chosen
	 * @return the index for function table
	 */
	private static int getTableIndex(Program program, Vtable vtable, VtableMode mode) {
		Function[][] functionTable = vtable.getFunctionTables();
		if (functionTable.length == 0) {
			return 0; // No function tables, return with 0 early
		}
		if (functionTable.length == 1) {
			return 0; // Single function table, return with 0 early
		}

		if (mode == VtableMode.VS) {
			return functionTable.length - 1;
		}

		if (mode == VtableMode.GCC) {
			Memory mem = program.getMemory();
			DataType ptrDiff = GnuUtils.getPtrDiff_t(program.getDataTypeManager());
			int diffLen = ptrDiff.getLength();
			Settings settings = ptrDiff.getDefaultSettings();
			Address[] addresses = vtable.getTableAddresses();
			for (int i = 0; i < addresses.length; i++) {
				Address addr = addresses[i];
				int size = addr.getPointerSize();
				Address diffAddr = addr.subtract(size * 2);
				MemBuffer buf = new DumbMemBufferImpl(mem, diffAddr);
				Object value = ptrDiff.getValue(buf, settings, diffLen);
				if (!(value instanceof Scalar)) {
					throw new AssertException("Expected scalar datatype");
				}
				Scalar scalarValue = (Scalar) value;
				if (scalarValue.getValue() == 0) {
					return i;
				}
			}
			return 0; // Use default if failed to find zero diff table
		}

		return 0; // Zeroth table is also default if mode isn't supported
	}

	public static void processFunctionDefinitionName(DataType dataType) {
		try {
			String name = dataType.getName();
			DemangledObject demangled = DemanglerUtil.demangle(name);
			if (demangled == null) {
				String path = dataType.getDataTypePath().toString();
				if (path.charAt(0) == '/') {
					path = path.substring(1);
				}
				name = path.replaceAll("/", "::");
			}
			else {
				name = demangled.getNamespace() + "::" + demangled.getName();
			}
			name = name + "_t";
			dataType.setName(name);
		} catch (InvalidNameException | DuplicateNameException e) {}
	}

	/**
	 * Checks if function is pure by its name.
	 * @param function the function to check
	 * @return true if function is pure
	 */
	private static boolean isPureFunction(Function function) {
		String name = function.getName();
		if (name.equals("__cxa_pure_virtual")) return true;
		if (name.equals("__purecall")) return true;
		return false;
	}

	private static String getUniqueName(Function function, Function[] table, Structure structure) {
		String name = function.getName();
		DataTypeComponent[] components = structure.getComponents();
		int countInTable = 0;
		for (Function func : table) {
			if (func == null) continue;
			if (func.getName().equals(name)) {
				countInTable++;
			}
		}
		int countInStructure = 0;
		for (DataTypeComponent component : components) {
			String another = component.getFieldName();
			if (another == null) continue;
			if (another.equals(name)) {
				countInStructure++;
			}
			for (int i = 0; i < countInTable; i++) {
				another = name + "_" + i;
				if (another.equals(component.getFieldName())) {
					countInStructure++;
					break; // Found already
				}
			}
		}
		if (countInTable < 2) {
			if (countInStructure > 0) {
				throw new AssertException("Mismatch between count in table and structure");
			}
			return name;
		}
		String unique = name + "_" + countInStructure;
		return unique;
	}

	/**
	 * Gets the DataType representation of the _vptr for the specified ClassTypeInfo.
	 * @param program the program containing the ClassTypeInfo
	 * @param type the ClassTypeInfo
	 * @param mode which vtable to pick
	 * @return the ClassTypeInfo's _vptr DataType
	 */
	public static DataType getVptrDataType(Program program, ClassTypeInfo type, VtableMode mode) {
		try {
			Vtable vtable = type.getVtable();
			CategoryPath path =
				new CategoryPath(TypeInfoUtils.getCategoryPath(type), type.getName());
			DataTypeManager dtm = program.getDataTypeManager();
			Structure struct = new StructureDataType(path, type.getName() + "::" + VtableModel.SYMBOL_NAME + "_t", 0, dtm);
			Function[][] functionTable = vtable.getFunctionTables();
			int i = getTableIndex(program, vtable, mode);
			if (functionTable.length > 0 && functionTable[i].length > 0) {
				for (Function function : functionTable[i]) {
					if (function != null) {
						String name = getUniqueName(function, functionTable[i], struct);
						if (isPureFunction(function)) {
							DataType dt = dtm.getPointer(VoidDataType.dataType);
							struct.add(dt, dt.getLength(), name, null);
							continue;
						}
						DataType dt = new FunctionDefinitionDataType(function, false);
						dt.setCategoryPath(path);
						processFunctionDefinitionName(dt);
						if (dtm.contains(dt)) {
							dt = dtm.getDataType(dt.getDataTypePath());
						} else {
							dt = dtm.resolve(dt, DataTypeConflictHandler.KEEP_HANDLER);
						}
						dt = dtm.getPointer(dt);
						struct.add(dt, dt.getLength(), name, null);
					} else {
						struct.add(PointerDataType.dataType);
					}
				}
			}
			struct = (Structure) dtm.resolve(struct, DataTypeConflictHandler.REPLACE_HANDLER);
			return dtm.getPointer(struct);
		} catch (DuplicateNameException e) {
			throw new AssertException("Ghidra-Cpp-Class-Analyzer: "+e.getMessage(), e);
		}
	}

	/**
	 * Gets the DataType representation of the _vptr for the specified ClassTypeInfo.
	 * @param program the program containing the ClassTypeInfo
	 * @param type the ClassTypeInfo
	 * @param path The category path to place the datatype in.
	 * @return the ClassTypeInfo's _vptr DataType
	 * @deprecated the path parameter is now ignored
	 */
	@Deprecated(forRemoval=true)
	public static DataType getVptrDataType(Program program, ClassTypeInfo type, CategoryPath path, VtableMode mode) {
		return getVptrDataType(program, type, mode);
	}

	public static Map<ClassTypeInfo, Integer> getBaseOffsets(ClassTypeInfo type) {
		if (!type.hasParent()) {
			return Collections.emptyMap();
		}
		if (type.getParentModels().length == 1) {
			if (Vtable.isValid(type.getVtable())) {
				GnuVtable vtable = (GnuVtable) type.getVtable();
				long offset = vtable.getOffset(0, 0);
				if (offset < Long.MAX_VALUE && offset > 0) {
					return Map.of(type.getParentModels()[0], (int) offset);
				}
			}
			return Map.of(type.getParentModels()[0], 0);
		}
		if (type instanceof VmiClassTypeInfoModel) {
			VmiClassTypeInfoModel vmi = (VmiClassTypeInfoModel) type;
			List<Long> offsets = vmi.getOffsets();
			ClassTypeInfo[] parents = vmi.getParentModels();
			Map<ClassTypeInfo, Integer> result = new HashMap<>(parents.length);
			for (int i = 0; i < parents.length; i++) {
				result.put(parents[i], offsets.get(i).intValue());
			}
			return result;
		}
		throw new IllegalArgumentException("Ghidra-Cpp-Class-Analyzer: type must be a GNU ClassTypeInfo");
	}

	public static GhidraClass getGhidraClassFromTypeName(Program program, String typename) {
		Namespace ns = TypeInfoUtils.getNamespaceFromTypeName(program, typename);
		if (ns instanceof GhidraClass) {
			return (GhidraClass) ns;
		}
		try {
			if (!ns.isGlobal()) {
				return NamespaceUtils.convertNamespaceToClass(ns);
			}
		} catch (InvalidInputException e) {
			// impossible
			throw new AssertException(e);
		}
		throw new AssertException(
			"Ghidra-Cpp-Class-Analyzer: failed to get GhidraClass from typename "
			+ typename);
	}

	public static int getMaxVtableCount(ClassTypeInfo type) {
		if (type instanceof VmiClassTypeInfoModel) {
			return doGetMaxVtableCount(type);
		}
		if (type instanceof GnuClassTypeInfoDB) {
			if (((GnuClassTypeInfoDB) type).getTypeId() == TypeId.VMI_CLASS) {
				return doGetMaxVtableCount(type);
			}
		}
		try {
			return type.getVirtualParents().size()+1;
		}
		catch (NullPointerException e) {
			return 1;
		}
	}

	private static int doGetMaxVtableCount(ClassTypeInfo type) {
		Program program = type.getGhidraClass().getSymbol().getProgram();
		int defaultMax = type.getVirtualParents().size()+1;
		BaseClassTypeInfoModel[] bases;
		if (type instanceof VmiClassTypeInfoModel) {
			// vmi already has it constructed so check first
			bases = ((VmiClassTypeInfoModel) type).getBases();
		} else {
			bases = VmiClassTypeInfoModel.getBases(program, type.getAddress());
		}
		int offset = Arrays.stream(bases)
			.map(BaseClassTypeInfoModel::getVirtualBases)
			.flatMap(Set::stream)
			.mapToInt(BaseClassTypeInfoModel::getOffset)
			.min()
			.orElse(0);
		if (offset >= 0) {
			return type.getVirtualParents().size()+1;
		}
		return Math.max(defaultMax, Math.abs(offset) / program.getDefaultPointerSize() - 1);
	}

}

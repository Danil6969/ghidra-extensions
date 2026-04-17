package cppclassanalyzer.vs;

import static ghidra.program.model.data.Undefined.isUndefined;

import java.util.Map;

import cppclassanalyzer.data.ClassTypeInfoManager;
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import ghidra.app.cmd.data.rtti.*;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.app.cmd.data.rtti.gcc.TypeInfoUtils;
import ghidra.app.util.datatype.microsoft.MSDataTypeUtils;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.DuplicateNameException;

public class VsCppClassBuilder extends AbstractCppClassBuilder {

	private static final String VFPTR = "_vfptr";
	private static final String VBPTR = "_vbptr";
	private static final String NOVFPTR = "_novfptr";

	public VsCppClassBuilder(VsClassTypeInfo type) {
		super(type);
	}

	@Override
	protected AbstractCppClassBuilder getParentBuilder(ClassTypeInfo parent) {
		return new VsCppClassBuilder((VsClassTypeInfo) parent);
	}

	@Override
	protected void addVptr(Structure struct) {
		try {
			addPointers(struct);
		} catch (InvalidDataTypeException e) {
			return;
		}
	}

	private int getSliceOffset(DataType parentDatatype) {
		if (!(parentDatatype instanceof Structure)) {
			return -1;
		}
		DataTypeManager manager = parentDatatype.getDataTypeManager();
		if (manager == null) {
			return -1;
		}
		int pointerSize = manager.getDataOrganization().getPointerSize();
		Structure parentStructure = (Structure) parentDatatype;
		int sliceOffset = pointerSize;
		if (parentStructure.getLength() <= sliceOffset) {
			return sliceOffset;
		}
		DataTypeComponent sliceComp = parentStructure.getComponentContaining(sliceOffset);
		if (sliceComp.getOffset() != sliceOffset) {
			return -1;
		}
		return sliceOffset;
	}

	private String getPureSuperName(String name) {
		if (name.startsWith(SUPER)) {
			name = name.substring(SUPER.length());
		}
		if (name.startsWith(NOVTABLE)) {
			name = name.substring(NOVTABLE.length());
		}
		return name;
	}

	private Structure getNovtableDatatype(DataType parentDatatype, String prefix) {
		try {
			DataTypeManager manager = parentDatatype.getDataTypeManager();
			CategoryPath parentPath = parentDatatype.getCategoryPath();
			String parentName = getPureSuperName(parentDatatype.getName());
			if (!parentName.equals(parentDatatype.getName())) {
				if (parentPath.getParent() != null) {
					parentPath = parentPath.getParent();
				}
			}
			String newName = prefix + parentName;
			CategoryPath newPath = new CategoryPath(parentPath, parentName);
			DataType existingDatatype = manager.getDataType(newPath, newName);
			if (existingDatatype != null) {
				if (existingDatatype instanceof Structure) {
					return (Structure) existingDatatype;
				}
			}
			Structure novtableDatatype = new StructureDataType(newPath, newName, 0, manager);
			novtableDatatype.setCategoryPath(newPath);
			novtableDatatype.setName(newName);
			return novtableDatatype;
		} catch (InvalidNameException | DuplicateNameException e) {
			return null;
		}
	}

	private void addVfptr(Structure struct, int offset) {
		ClassTypeInfo type = getType();
		Program program = getProgram();
		DataType vfptr = ClassTypeInfoUtils.getVptrDataType(program, type, ClassTypeInfoUtils.VtableMode.VS);
		Structure novtableDatatype = getNovtableDatatype(struct, NOVTABLE);
		if (novtableDatatype != null) {
			replaceComponent(struct, novtableDatatype, NOVFPTR, offset + vfptr.getLength());
		}
		replaceComponent(struct, vfptr, VFPTR, offset);
	}


	/**  {@link Rtti4Model#getVbTableOffset} */
	private void addVbptr(Structure struct, int offset) throws InvalidDataTypeException {
		Program program = getProgram();
		DataTypeManager dtm = program.getDataTypeManager();
		int ptrSize = program.getDefaultPointerSize();
		DataType vbptr = dtm.getPointer(
			MSDataTypeUtils.getPointerDisplacementDataType(program), ptrSize);
		Structure novtableDatatype = getNovtableDatatype(struct, NOVTABLE);
		if (novtableDatatype != null) {
			replaceComponent(struct, novtableDatatype, NOVFPTR, offset + vbptr.getLength());
		}
		replaceComponent(struct, vbptr, VBPTR, offset);
	}

	private void addPointers(Structure struct) throws InvalidDataTypeException {
		VsClassTypeInfo type = getType();
		int offset = 0;
		Vtable vtable = type.getVtable();
		if (Vtable.isValid(vtable)) {
			addVfptr(struct, offset);
			offset = getProgram().getDefaultPointerSize();
		}
		if (!type.getVirtualParents().isEmpty()) {
			addVbptr(struct, offset);
		}
	}

	@Override
	protected Map<ClassTypeInfo, Integer> getBaseOffsets() {
		return getType().getBaseOffsets();
	}

	@Override
	protected VsClassTypeInfo getType() {
		return (VsClassTypeInfo) super.getType();
	}
}

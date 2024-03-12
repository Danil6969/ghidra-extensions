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
		if (name.startsWith(NOVFPTR)) {
			name = name.substring(NOVFPTR.length());
		}
		if (name.startsWith(NOVBPTR)) {
			name = name.substring(NOVBPTR.length());
		}
		return name;
	}

	private Structure getSlicedDatatype(DataType parentDatatype, String prefix) {
		try {
			int sliceOffset = getSliceOffset(parentDatatype);
			if (sliceOffset < 0) {
				return null;
			}
			CategoryPath newPath = new CategoryPath(parentDatatype.getCategoryPath(), parentDatatype.getName());
			String newName = prefix + getPureSuperName(parentDatatype.getName());
			DataType existingDatatype = parentDatatype.getDataTypeManager().getDataType(newPath, newName);
			if (existingDatatype != null) {
				if (existingDatatype instanceof Structure) {
					return (Structure) existingDatatype;
				}
			}
			Structure novtableDatatype = new StructureDataType(newPath, newName, 0, parentDatatype.getDataTypeManager());
			novtableDatatype.setCategoryPath(newPath);
			novtableDatatype.setName(newName);
			Structure parentStructure = ((Structure) parentDatatype);
			DataTypeComponent sliceComponent = parentStructure.getComponentContaining(sliceOffset);
			if (sliceComponent == null) {
				return novtableDatatype;
			}
			int sliceOrdinal = sliceComponent.getOrdinal();
			int number = parentStructure.getNumComponents();
			for (int i = sliceOrdinal; i < number; i++) {
				DataTypeComponent parentComponent = parentStructure.getComponent(i);
				DataType componentDatatype = parentComponent.getDataType();
				int componentLength = parentComponent.getLength();
				String componentName = parentComponent.getFieldName();
				String componentComment = parentComponent.getComment();
				novtableDatatype.add(componentDatatype, componentLength, componentName, componentComment);
			}
			return novtableDatatype;
		} catch (InvalidNameException | DuplicateNameException e) {
			return null;
		}
	}

	private void addVfptr(Structure struct, int offset) {
		ClassTypeInfo type = getType();
		Program program = getProgram();
		DataType vfptr = ClassTypeInfoUtils.getVptrDataType(program, type, ClassTypeInfoUtils.VtableMode.VS);
		DataTypeComponent comp = struct.getComponentContaining(offset);
		if (comp == null || isUndefined(comp.getDataType())) {
			replaceComponent(struct, vfptr, VFPTR, offset);
		}
		else {
			if (comp.getFieldName().startsWith(SUPER)) {
				DataType parentDatatype = comp.getDataType();
				Structure novtableDatatype = getSlicedDatatype(parentDatatype, NOVFPTR);
				struct.clearComponent(comp.getOrdinal());
				if (novtableDatatype != null) {
					String newName = NOVFPTR + getPureSuperName(parentDatatype.getName());
					replaceComponent(struct, novtableDatatype, newName, offset + getSliceOffset(parentDatatype));
				}
			}
			replaceComponent(struct, vfptr, VFPTR, offset);
		}
	}


	/**  {@link Rtti4Model#getVbTableOffset} */
	private void addVbptr(Structure struct, int offset) throws InvalidDataTypeException {
		Program program = getProgram();
		DataTypeManager dtm = program.getDataTypeManager();
		int ptrSize = program.getDefaultPointerSize();
		DataType vbptr = dtm.getPointer(
			MSDataTypeUtils.getPointerDisplacementDataType(program), ptrSize);
		DataTypeComponent comp = struct.getComponentContaining(offset);
		if (comp == null || isUndefined(comp.getDataType())) {
			replaceComponent(struct, vbptr, VBPTR, offset);
		}
		else {
			if (comp.getFieldName().startsWith(NOVFPTR)) {
				DataType parentDatatype = comp.getDataType();
				Structure novtableDatatype = getSlicedDatatype(parentDatatype, NOVBPTR);
				struct.clearComponent(comp.getOrdinal());
				if (novtableDatatype != null) {
					String newName = NOVBPTR + getPureSuperName(parentDatatype.getName());
					replaceComponent(struct, novtableDatatype, newName, offset + getSliceOffset(parentDatatype));
				}
			}
			replaceComponent(struct, vbptr, VBPTR, offset);
		}
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

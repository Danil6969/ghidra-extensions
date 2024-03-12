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

	private int getSliceOffset(DataType parentDatatype, int offset) {
		if (!(parentDatatype instanceof Structure)) {
			return -1;
		}
		DataTypeManager manager = parentDatatype.getDataTypeManager();
		if (manager == null) {
			return -1;
		}
		int pointerSize = manager.getDataOrganization().getPointerSize();
		Structure novtableDatatype = (Structure) parentDatatype;
		int sliceOffset = offset + pointerSize;
		if (novtableDatatype.getLength() <= sliceOffset) {
			return -1;
		}
		DataTypeComponent sliceComp = novtableDatatype.getComponentContaining(sliceOffset);
		if (sliceComp.getOffset() != sliceOffset) {
			return -1;
		}
		return sliceOffset;
	}

	private Structure getNovtableDatatype(DataType parentDatatype, int offset, ClassTypeInfoManager classManager) {
		try {
			int sliceOffset = getSliceOffset(parentDatatype, offset);
			if (sliceOffset < 0) {
				return null;
			}
			CategoryPath newPath = new CategoryPath(parentDatatype.getCategoryPath(), parentDatatype.getName());
			String newName = NOVTABLE + parentDatatype.getName();
			StructureDataType novtableDatatype = new StructureDataType(newPath, newName, parentDatatype.getLength(), parentDatatype.getDataTypeManager());
			novtableDatatype.replaceWith(parentDatatype);
			novtableDatatype.setCategoryPath(newPath);
			novtableDatatype.setName(NOVTABLE + parentDatatype.getName());
			DataTypeComponent sliceComp = novtableDatatype.getComponentContaining(sliceOffset);
			int sliceOrdinal = sliceComp.getOrdinal();
			for (int i = 0; i < sliceOrdinal; i++) {
				novtableDatatype.clearComponent(i);
			}
			return novtableDatatype;
		} catch (InvalidNameException e) {
			return null;
		}
	}

	private void addVfptr(Structure struct, int offset) {
		ClassTypeInfo type = getType();
		Program program = getProgram();
		DataType vfptr = ClassTypeInfoUtils.getVptrDataType(program, type, ClassTypeInfoUtils.VtableMode.VS);
		DataTypeComponent component = struct.getComponentContaining(offset);
		if (component == null || isUndefined(component.getDataType())) {
			replaceComponent(struct, vfptr, VFPTR, offset);
		} else {
			if (component.getFieldName().startsWith(SUPER)) {
				if (!(type instanceof ClassTypeInfoDB)) {
					throw new AssertException("No way to get manager");
				}
				ClassTypeInfoManager classManager = ((ClassTypeInfoDB) type).getManager();
				DataType parentDatatype = component.getDataType();
				Structure novtableDatatype = getNovtableDatatype(parentDatatype, offset, classManager);
				if (novtableDatatype != null) {
					;
				}
				struct.clearComponent(component.getOrdinal());
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
		} else if (comp.getFieldName() == null || !comp.getFieldName().startsWith(SUPER)) {
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

package cppclassanalyzer.borland.delphi;

import cppclassanalyzer.data.typeinfo.AbstractClassTypeInfoDB;
import ghidra.app.cmd.data.rtti.AbstractCppClassBuilder;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.program.model.data.Structure;

import java.util.Map;

public class BorlandDelphiClassBuilder extends AbstractCppClassBuilder {

	public BorlandDelphiClassBuilder(ClassTypeInfo type) {
		super(type);
	}

	@Override
	protected AbstractCppClassBuilder getParentBuilder(ClassTypeInfo parent) {
		return new BorlandDelphiClassBuilder(parent);
	}

	@Override
	protected void addVptr(Structure struct) {
		return; //TODO
	}

	@Override
	protected Map<ClassTypeInfo, Integer> getBaseOffsets() {
		ClassTypeInfo type = getType();
		if (type instanceof AbstractClassTypeInfoDB) {
			return ((AbstractClassTypeInfoDB) type).getBaseOffsets();
		}
		return ClassTypeInfoUtils.getBaseOffsets(type); //TODO?
	}
}

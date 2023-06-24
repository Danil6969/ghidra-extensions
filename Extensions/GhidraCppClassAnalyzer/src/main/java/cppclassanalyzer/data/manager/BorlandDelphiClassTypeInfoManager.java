package cppclassanalyzer.data.manager;

import cppclassanalyzer.data.manager.caches.ProgramRttiCachePair;
import cppclassanalyzer.data.manager.tables.ProgramRttiTablePair;
import cppclassanalyzer.data.typeinfo.BorlandDelphiClassTypeInfoDB;
import cppclassanalyzer.data.vtable.VftableDB;
import cppclassanalyzer.database.record.ClassTypeInfoRecord;
import cppclassanalyzer.database.record.VtableRecord;
import cppclassanalyzer.service.ClassTypeInfoManagerService;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;

public final class BorlandDelphiClassTypeInfoManager extends ClassTypeInfoManagerDB {

	public BorlandDelphiClassTypeInfoManager(ClassTypeInfoManagerService service, ProgramDB program) {
		super(service, program);
	}

	@Override
	protected RttiRecordWorker getWorker(ProgramRttiTablePair tables,
			ProgramRttiCachePair caches) {
		return new BorlandDelphiRttiRecordWorker(tables, caches);
	}

	@Override
	public boolean isTypeInfo(Address address) {
		return false;
	}

	private final class BorlandDelphiRttiRecordWorker extends RttiRecordWorker {

		BorlandDelphiRttiRecordWorker(ProgramRttiTablePair tables, ProgramRttiCachePair caches) {
			super(tables, caches);
		}

		@Override
		BorlandDelphiClassTypeInfoDB buildType(ClassTypeInfoRecord record) {
			return new BorlandDelphiClassTypeInfoDB(this, record);
		}

		@Override
		BorlandDelphiClassTypeInfoDB buildType(ClassTypeInfo type, ClassTypeInfoRecord record) {
			return new BorlandDelphiClassTypeInfoDB(this, type, record);
		}

		@Override
		VftableDB buildVtable(VtableRecord record) {
			return null; //TODO
		}

		@Override
		VftableDB buildVtable(Vtable vtable, VtableRecord record) {
			return null; //TODO
		}

	}

}

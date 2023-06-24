package cppclassanalyzer.provider;

import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.data.manager.BorlandDelphiClassTypeInfoManager;
import cppclassanalyzer.plugin.HeadlessClassTypeInfoManagerService;
import cppclassanalyzer.service.ClassTypeInfoManagerService;
import cppclassanalyzer.service.RttiManagerProvider;
import cppclassanalyzer.utils.CppClassAnalyzerUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Program;

import static ghidra.util.SystemUtilities.isInHeadlessMode;

public class BorlandDelphiRttiManagerProvider implements RttiManagerProvider {
	public static final BorlandDelphiRttiManagerProvider INSTANCE = new BorlandDelphiRttiManagerProvider();

	@Override
	public boolean canProvideManager(Program program) {
		String compilerIdString = program.getCompilerSpec().getCompilerSpecID().getIdAsString().toLowerCase();
		return compilerIdString.equals("borlanddelphi");
	}

	@Override
	public ProgramClassTypeInfoManager getManager(Program program) {
		if (!canProvideManager(program)) {
			return null;
		}
		ClassTypeInfoManagerService service;
		if (isInHeadlessMode()) {
			service = HeadlessClassTypeInfoManagerService.getInstance();
		} else {
			PluginTool tool = CppClassAnalyzerUtils.getTool(program);
			service = tool.getService(ClassTypeInfoManagerService.class);
		}
		return new BorlandDelphiClassTypeInfoManager(service, (ProgramDB) program);
	}
}

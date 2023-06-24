package cppclassanalyzer.provider;

import ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin.PEUtil;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Program;

import cppclassanalyzer.data.ProgramClassTypeInfoManager;
import cppclassanalyzer.data.manager.VsClassTypeInfoManager;
import cppclassanalyzer.plugin.HeadlessClassTypeInfoManagerService;
import cppclassanalyzer.service.ClassTypeInfoManagerService;
import cppclassanalyzer.service.RttiManagerProvider;
import cppclassanalyzer.utils.CppClassAnalyzerUtils;

import static ghidra.util.SystemUtilities.isInHeadlessMode;

public final class VsRttiManagerProvider implements RttiManagerProvider {

	public static final VsRttiManagerProvider INSTANCE = new VsRttiManagerProvider();

	@Override
	public boolean canProvideManager(Program program) {
		String compilerIdString = program.getCompilerSpec().getCompilerSpecID().getIdAsString().toLowerCase();
		boolean res = compilerIdString.equals("windows");
		res |= compilerIdString.equals("clangwindows");
		res &= PEUtil.canAnalyze(program);
		return res;
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
		return new VsClassTypeInfoManager(service, (ProgramDB) program);
	}
}

package ghidra.app.cmd.data.rtti.borland.delphi.helpers.system;

import ghidra.app.cmd.data.rtti.borland.delphi.helpers.HelperFunction;

public class HandleFinally extends HelperFunction {
	@Override
	public String getName() {
		return "System.@HandleFinally";
	}

	@Override
	public boolean isValid() {
		return true;
	}
}

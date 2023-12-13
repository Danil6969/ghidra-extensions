package ghidra.app.cmd.data.rtti.borland.delphi.helpers.system;

import ghidra.app.cmd.data.rtti.borland.delphi.helpers.HelperFunction;

public class NotifyExceptFinally extends HelperFunction {
	@Override
	public String getName() {
		return "System.NotifyExceptFinally";
	}

	@Override
	public boolean isValid() {
		return true;
	}
}

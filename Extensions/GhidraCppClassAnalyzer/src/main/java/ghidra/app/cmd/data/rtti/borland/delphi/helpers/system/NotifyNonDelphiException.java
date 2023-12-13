package ghidra.app.cmd.data.rtti.borland.delphi.helpers.system;

import ghidra.app.cmd.data.rtti.borland.delphi.helpers.HelperFunction;

public class NotifyNonDelphiException extends HelperFunction {
	@Override
	public String getName() {
		return "System.NotifyNonDelphiException";
	}

	@Override
	public boolean isValid() {
		return true;
	}
}

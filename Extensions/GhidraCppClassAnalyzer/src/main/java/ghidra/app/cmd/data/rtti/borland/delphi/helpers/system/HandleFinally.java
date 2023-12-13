package ghidra.app.cmd.data.rtti.borland.delphi.helpers.system;

import ghidra.app.cmd.data.rtti.borland.delphi.helpers.HelperFunction;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

import java.math.BigInteger;

public class HandleFinally extends HelperFunction {
	@Override
	public String getName() {
		return "System.@HandleFinally";
	}

	@Override
	public boolean isValid(Program program, Address address) {
		Listing listing = program.getListing();

		Address currentAddress = address;
		Instruction instruction0 = listing.getInstructionAt(currentAddress);
		if (instruction0 == null) {
			return false;
		}
		if (!instruction0.toString().equals("MOV EAX,dword ptr [ESP + 0x4]")) {
			return false;
		}

		currentAddress = currentAddress.add(instruction0.getLength());
		Instruction instruction1 = listing.getInstructionAt(currentAddress);
		if (instruction1 == null) {
			return false;
		}
		if (!instruction1.toString().equals("TEST dword ptr [EAX + 0x4],0x6")) {
			return false;
		}

		currentAddress = currentAddress.add(instruction1.getLength());
		Instruction instruction2 = listing.getInstructionAt(currentAddress);
		if (instruction2 == null) {
			return false;
		}
		BigInteger difference = new BigInteger("95", 16);
		BigInteger targetOffset = currentAddress.getOffsetAsBigInteger().add(difference);
		if (!instruction2.toString().equals("JZ " + offsetToString(targetOffset, 8))) {
			return false;
		}

		return true;
	}
}

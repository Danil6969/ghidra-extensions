package ghidra.app.cmd.data.rtti.borland.delphi.helpers;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public abstract class HelperFunction {
	public abstract String getName();
	public abstract boolean isValid(Program program, Address address);

	public Address[] getMatches(Program program, AddressRange[] ranges) {
		List<Address> list = new ArrayList<>();
		Listing listing = program.getListing();
		for (AddressRange range : ranges) {
			Address minAddress = range.getMinAddress();
			InstructionIterator instructions = listing.getInstructions(minAddress, true);
			while (instructions.hasNext()) {
				Instruction instruction = instructions.next();
				Address address = instruction.getAddress();
				if (!isValid(program, address)) {
					continue;
				}
				if (list.contains(address)) {
					continue;
				}
				list.add(address);
			}
		}
		return list.toArray(new Address[list.size()]);
	}

	protected String offsetToString(BigInteger offset, int alignment) {
		StringBuilder builder = new StringBuilder();
		builder.append(offset.toString(16));
		builder.reverse();
		while (builder.length() < alignment) {
			builder.append('0');
		}
		builder.append('x');
		builder.append('0');
		builder.reverse();
		return builder.toString();
	}
}

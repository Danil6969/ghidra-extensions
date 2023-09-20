package orbis.loader.emc;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.List;

import ghidra.app.util.DomainObjectService;
import ghidra.app.util.Option;
import ghidra.app.util.OptionException;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.program.model.util.VoidPropertyMap;
import ghidra.util.exception.AssertException;
import ghidra.util.map.TypeMismatchException;
import ghidra.util.task.TaskMonitor;

import orbis.bin.ipl.IplHeader;

public class IplExporter extends Exporter {

    public IplExporter() {
        super("IplExporter", "", null);
    }

    @Override
    public List<Option> getOptions(DomainObjectService domainObjectService) {
        return EMPTY_OPTIONS;
    }

    @Override
    public void setOptions(List<Option> list) throws OptionException {
        // no options for this exporter
    }

    @Override
	public boolean export(File file, DomainObject domainObj, AddressSetView addrSet,
			TaskMonitor monitor) throws IOException, ExporterException {
        if (!(domainObj instanceof Program)) {
            // impossible
            log.appendMsg("Unsupported file type");
            return false;
        }
        Program program = (Program) domainObj;
        PropertyMapManager man = program.getUsrPropertyManager();
        try {
            VoidPropertyMap map = man.getVoidPropertyMap(GhidraOrbisIplLoader.IPL_PROPERTY_NAME);
            if (map == null) {
                log.appendMsg("Not an ipl file");
                return false;
            }
        } catch (TypeMismatchException e) {
            log.appendMsg("Not an ipl file");
            return false;
        }
		Memory memory = program.getMemory();
        List<FileBytes> bytes = memory.getAllFileBytes();
        if (bytes.size() < 2) {
            // unexpected
            log.appendMsg("Missing file bytes, can't export");
            return false;
        }
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        StringPropertyMap keys = man.getStringPropertyMap(GhidraOrbisIplLoader.MAP_NAME);
        FileBytes hb = bytes.get(0);
        bytes = bytes.subList(1, bytes.size());
        byte[] data = new byte[(int) hb.getSize()];
        hb.getModifiedBytes(hb.getSize(), data);
        long size = bytes.stream()
            .mapToLong(FileBytes::getSize)
            .sum();

        // iff this becomes a problem it'll be corrected
        ByteBuffer body = ByteBuffer.allocate((int) size);
        bytes.stream()
            .map(IplExporter::toBuffer)
            .forEachOrdered(body::put);
        IplHeader header = new IplHeader(toBuffer(hb), body);
        String cipherKey = keys.getString(space.getAddress(0));
        String hasherKey = keys.getString(space.getAddress(1));
        try {
            header.encrypt(cipherKey, hasherKey);
        } catch (Exception e) {
            log.appendException(e);
            return false;
        }
        try (FileOutputStream os = new FileOutputStream(file)) {
            try (InputStream is = header.getHeaderInputStream()) {
                is.transferTo(os);
            }
            try (InputStream is = header.getBodyInputStream()) {
                is.transferTo(os);
            }
        } catch (Exception e) {
            log.appendException(e);
            return false;
        }
        return true;
    }

    private static ByteBuffer toBuffer(FileBytes bytes) {
        try {
            byte[] data = new byte[(int) bytes.getSize()];
            ByteBuffer buf = ByteBuffer.wrap(data);
            bytes.getModifiedBytes(0, data);
            return buf;
        } catch (IOException e) {
            throw new AssertException(e);
        }
    }

}

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class DecompileFunction extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("usage: DecompileFunction <function_address>");
            return;
        }

        Address address;
        try {
            address = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(args[0]);
        } catch (Exception ex) {
            printerr("invalid address: " + args[0]);
            return;
        }

        FunctionManager manager = currentProgram.getFunctionManager();
        Function function = manager.getFunctionContaining(address);
        if (function == null) {
            function = manager.getFunctionAt(address);
        }
        if (function == null) {
            printerr("function not found at or containing: " + address);
            return;
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        DecompileResults results = decompiler.decompileFunction(function, 60, monitor);

        println("{"function":"" + function.getName() + "",");
        println(" "entry":"" + function.getEntryPoint() + "",");
        println(" "success":" + results.decompileCompleted() + ",");
        if (!results.decompileCompleted()) {
            println(" "error":"" + results.getErrorMessage().replace(""", "'") + ""}");
            decompiler.dispose();
            return;
        }

        String c = results.getDecompiledFunction().getC();
        c = c.replace("\", "\\").replace(""", "\"").replace("
", "\n");
        println(" "pseudo_c":"" + c + ""}");
        decompiler.dispose();
    }
}

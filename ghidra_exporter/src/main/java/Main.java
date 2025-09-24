
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.bson.Document;
import org.bson.codecs.configuration.CodecProvider;
import org.bson.codecs.configuration.CodecRegistries;
import org.bson.codecs.configuration.CodecRegistry;
import org.bson.codecs.pojo.PojoCodecProvider;

import com.google.gson.Gson;
import com.mongodb.MongoClientSettings;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;



public class Main extends GhidraScript {
    private final static Pattern stackPtr = Pattern.compile("ptr \\[[^]]*?[BS]P.+]");
    private final CodeUnitFormat format = new CodeUnitFormat(CodeUnitFormatOptions.ShowBlockName.NEVER, CodeUnitFormatOptions.ShowNamespace.NEVER);
    MongoCollection<Document> functionCollection;
    private FunctionManager functionManager;
    private SymbolTable symbolTable;
    private ProgramBasedDataTypeManager dataTypeManager;
    private MongoClient mongoClient;
    private BasicBlockModel basicBlockModel;
    private String programId, optLevel;
    private static boolean GO = false;

    public void formatInstruction(StringBuilder output, Instruction instruction, HashMap<String, String> symbolMap) {
        Symbol symbol = symbolTable.getPrimarySymbol(instruction.getAddress());
        if (symbol != null) {
            output.append(symbolMap.getOrDefault(symbol.getName(), symbol.getName())).append(":\n");
        }
        String representationString;
        try {
            representationString = format.getRepresentationString(instruction);
        } catch (UnsupportedOperationException e) {
            representationString = instruction.toString();
        }
        for (Map.Entry<String, String> symbolEntry : symbolMap.entrySet()) {
            representationString = representationString.replace(symbolEntry.getKey(), symbolEntry.getValue());
        }

        // print stack offset
        int op_count = instruction.getNumOperands();
        for (int i = 0; i < op_count; i++) {
            if ((instruction.getOperandType(i) != (OperandType.DYNAMIC | OperandType.ADDRESS))) {
                continue;
            }
            Object[] opObjects = instruction.getOpObjects(i);

            for (var o : opObjects) {
                if (o instanceof Register r) {
                    if (r.getName().contains("SP") || r.getName().contains("BP")) {
                        String opStr = instruction.getDefaultOperandRepresentation(i);
                        var numMatch = stackPtr.matcher(opStr);
                        if (!numMatch.find()) continue;
                        String numStackPtr = numMatch.group();
                        representationString = stackPtr.matcher(representationString).replaceAll(numStackPtr);
                        break;
                    }
                }
            }
        }

        output.append(representationString);
        output.append('\n');
    }

    public List<BasicBlockInfo> formatBasicBlock(Function function, HashMap<String, String> symbolMap) throws CancelledException {
        AddressSet body = new AddressSet(function.getBody());
        Listing listing = currentProgram.getListing();
        CodeBlockIterator codeBlocks = basicBlockModel.getCodeBlocksContaining(body, monitor);
        List<BasicBlockInfo> result = new ArrayList<>();

        while (codeBlocks.hasNext() && !monitor.isCancelled()) {
            CodeBlock codeUnit = codeBlocks.next();
            BasicBlockInfo info = new BasicBlockInfo();
            info.id= symbolMap.getOrDefault(codeUnit.getName(), codeUnit.getName());
            StringBuilder content = new StringBuilder();
            InstructionIterator instructions = listing.getInstructions(codeUnit, true);

            while (instructions.hasNext()) {
                Instruction instruction = instructions.next();
                formatInstruction(content, instruction, symbolMap);
            }
            info.content = content.toString();

            var sources = codeUnit.getSources(monitor);
            var sourceBasicBlockEdgeList = new ArrayList<BasicBlockEdge>();
            while (sources.hasNext()) {
                var codeBlockReference = sources.next();
                String sourceBlockName = codeBlockReference.getSourceBlock().getName();
                if(codeBlockReference.getFlowType().isCall() && !isReferenceFunction(function, sourceBlockName)){
                    continue;
                }
                sourceBasicBlockEdgeList.add(new BasicBlockEdge(
                        symbolMap.getOrDefault(sourceBlockName, sourceBlockName),
                        codeBlockReference.getFlowType().getDisplayString()));
            }
            info.ins = sourceBasicBlockEdgeList;

            var destinations = codeUnit.getDestinations(monitor);
            var destinationsBasicBlockEdgeList = new ArrayList<BasicBlockEdge>();
            while (destinations.hasNext()) {
                var codeBlockReference = destinations.next();
                String destinationBlockName = codeBlockReference.getDestinationBlock().getName();
                if(codeBlockReference.getFlowType().isCall() && !isReferenceFunction(function, destinationBlockName)){
                    continue;
                }
                destinationsBasicBlockEdgeList.add(new BasicBlockEdge(
                        symbolMap.getOrDefault(destinationBlockName, destinationBlockName),
                        codeBlockReference.getFlowType().getDisplayString()));
            }
            info.outs = destinationsBasicBlockEdgeList;
            result.add(info);
        }
        if (monitor.isCancelled()) return null;
        return result;
    }


    public void formatAsm(StringBuilder output, Function function, HashMap<String, String> symbolMap) {
        AddressSet body = new AddressSet(function.getBody());
        Listing listing = currentProgram.getListing();
        InstructionIterator instructions = listing.getInstructions(body, true);

        while (instructions.hasNext() && !monitor.isCancelled()) {
            Instruction instruction = instructions.next();
            formatInstruction(output, instruction, symbolMap);
        }
    }

    public String formatDecompileCode(DecompileResults decompileResults) {
        if (decompileResults.getDecompiledFunction() == null) return null;
        return decompileResults.getDecompiledFunction().getC();
    }

    public List<String> getSourceCodeRange(Function f) {
        AddressSet body = new AddressSet(f.getBody());
        Listing listing = currentProgram.getListing();
        InstructionIterator instructions = listing.getInstructions(body, true);
        List<String> result = new ArrayList<>();

        while (instructions.hasNext() && !monitor.isCancelled()) {
            Instruction instruction = instructions.next();

            String preComment = instruction.getComment(CodeUnit.PRE_COMMENT);
            if (preComment != null) result.add(preComment);
        }
        return result;
    }

    public HashMap<String, String> buildSymbolMap(Function f) throws CancelledException {
        AddressSet body = new AddressSet(f.getBody());
        HashMap<String, String> output = new HashMap<>();
        CodeBlockIterator codeBlocks = basicBlockModel.getCodeBlocksContaining(body, monitor);

        Listing listing = currentProgram.getListing();
        InstructionIterator instructions = listing.getInstructions(body, true);
        int id = 0;
        while (instructions.hasNext() && !monitor.isCancelled()) {
            Instruction instruction = instructions.next();
            Symbol symbol = symbolTable.getPrimarySymbol(instruction.getAddress());
            if (symbol == null) continue;
            output.put(symbol.getName(), "LABEL_" + (id++));
        }
        while (codeBlocks.hasNext() && !monitor.isCancelled()) {
            CodeBlock codeBlock = codeBlocks.next();
            if (output.containsKey(codeBlock.getName())) {
                continue;
            }
            output.put(codeBlock.getName(), "LABEL_" + (id++));
        }
        return output;
    }

    public List<Structure> getStructuresUsedInFunction(DecompileResults decompileResults) {
        List<Structure> structList = new ArrayList<>();
        Set<String> seen = new HashSet<>(); // 去重：结构体名集合

        HighFunction highFunc = decompileResults.getHighFunction();
        if (highFunc == null) {
            println("无法获取 HighFunction");
            return structList;
        }

        // 遍历所有变量（局部 + 参数）
        for (Iterator<HighSymbol> it = highFunc.getLocalSymbolMap().getSymbols(); it.hasNext(); ) {
            HighSymbol symbol = it.next();
            HighVariable var = symbol.getHighVariable();
            if (var == null) continue;
            DataType dt = var.getDataType();
            Structure struct = extractStructure(dt);
            if (struct != null && seen.add(struct.getName())) {
                structList.add(struct);
            }
        }
        return structList;
    }

    public List<Structure> getAllUsedStructures(List<Structure> inputList) {
        List<Structure> result = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        Queue<Structure> queue = new LinkedList<>();

        for (Structure s : inputList) {
            if (seen.add(s.getName())) {
                queue.offer(s);
                result.add(s);
            }
        }

        while (!queue.isEmpty()) {
            Structure current = queue.poll();

            for (DataTypeComponent field : current.getComponents()) {
                DataType fieldType = field.getDataType();
                Structure embeddedStruct = extractStructure(fieldType);

                if (embeddedStruct != null && seen.add(embeddedStruct.getName())) {
                    result.add(embeddedStruct);
                    queue.offer(embeddedStruct);
                }
            }
        }
        if(GO){
            result.removeIf(structure -> {
                boolean pointer = structure.getLength() == 8 && (structure.getDisplayName().startsWith("*") || structure.getDisplayName().endsWith("*"));
                if (pointer) return true;
                boolean map = structure.getDisplayName().startsWith("map[");
                if (map) return true;
                boolean array = structure.getDisplayName().matches("^(\\[[0-9]*])+.*$");
                if (array) return true;
                return Stream.of("runtime.", "sync.", "string.", "error").anyMatch(s -> structure.getDisplayName().startsWith(s));
            });
        }

        return result;
    }

    private Structure extractStructure(DataType dt) {
        if (dt instanceof Structure) {
            return (Structure) dt;
        }
        if (dt instanceof Pointer) {
            DataType base = ((Pointer) dt).getDataType();
            if (base instanceof Structure) {
                return (Structure) base;
            }
        }
        if (dt instanceof Array) {
            DataType base = ((Array) dt).getDataType();
            if (base instanceof Structure) {
                return (Structure) base;
            }
        }
        return null;
    }

    public void formatStructure(StringBuilder output, Structure struct) {
        output.append("Structure Name: ").append(struct.getName()).append("\n");
        output.append("Size: ").append(struct.getLength()).append(" bytes\n");
        output.append("Field List:\n");
        for (DataTypeComponent component : struct.getComponents()) {
            String fieldName = component.getFieldName();
            String dataType = component.getDataType().getDisplayName();
            int offset = component.getOffset();
            int length = component.getLength();
            if (fieldName == null) continue;
            output.append(" Offset ").append(offset).append(" (Size: ").append(length).append(") -> ").append(fieldName).append(" : ").append(dataType).append("\n");
        }
    }

    public HashMap<String, String> getStringsUsedInFunction(Function function) {
        HashMap<String, String> result = new HashMap<>();

        Listing listing = function.getProgram().getListing();
        Data data;

        InstructionIterator instructions = listing.getInstructions(function.getBody(), true);

        while (instructions.hasNext() && !monitor.isCancelled()) {
            Instruction instr = instructions.next();

            for (Reference ref : instr.getReferencesFrom()) {
                if (ref.getReferenceType().isData()) {
                    Address target = ref.getToAddress();

                    // 获取符号名（如果有）
                    Symbol primarySymbol = currentProgram.getSymbolTable().getPrimarySymbol(target);
                    String primarySymbolName = (primarySymbol != null) ? primarySymbol.getName() : target.toString();

                    boolean isClangString = false;
                    for(var s : currentProgram.getSymbolTable().getSymbols(target)){
                        if(s.getName() != null && s.getName().startsWith("decgstr_")){
                            isClangString = true;
                            break;
                        }
                    }
                    if (isClangString) {
                        Address readPointer = target;
                        Memory memory = currentProgram.getMemory();
                        ByteArrayOutputStream baos = new ByteArrayOutputStream();
                        while(true){
                            byte b;
                            try {
                                b = memory.getByte(readPointer);
                            } catch (MemoryAccessException e) {
                                break;
                            }
                            if(b == 0) {
                                break;
                            }
                            baos.write(b);
                            readPointer = readPointer.add(1);
                        }
                        result.put(primarySymbolName, baos.toString());
                    } else {
                        data = listing.getDefinedDataAt(target);
                        if (data != null && data.isDefined()) {
                            DataType dt = data.getDataType();

                            // 判断是否是字符串类型
                            boolean isString = dt instanceof StringDataType || dt instanceof TerminatedStringDataType;
                            if (!isString && dt instanceof Array) {
                                isString = ((Array)dt).getDataType() instanceof CharDataType;
                            }
                            if (!isString) continue;
                            // 获取字符串内容
                            Object value = data.getValue();
                            if (value instanceof String) {
                                result.put(primarySymbolName, (String)value);
                            }
                        }
                    }
                }
            }
        }
        return result;
    }


    public HashMap<String, String> getFloatsUsedInFunction(Function function) {
        HashMap<String, String> result = new HashMap<>();

        Listing listing = function.getProgram().getListing();
        Data data;

        InstructionIterator instructions = listing.getInstructions(function.getBody(), true);

        while (instructions.hasNext() && !monitor.isCancelled()) {
            Instruction instr = instructions.next();

            for (Reference ref : instr.getReferencesFrom()) {
                if (ref.getReferenceType().isData()) {
                    Address target = ref.getToAddress();

                    // 获取符号名（如果有）
                    Symbol primarySymbol = currentProgram.getSymbolTable().getPrimarySymbol(target);
                    String primarySymbolName = (primarySymbol != null) ? primarySymbol.getName() : target.toString();

                    boolean isClangFloat = false;
                    for(var s : currentProgram.getSymbolTable().getSymbols(target)){
                        if(s.getName() != null && s.getName().startsWith("decgcpi_")){
                            isClangFloat = true;
                            break;
                        }
                    }
                    if (isClangFloat) {
                        Address readPointer = target;
                        Memory memory = currentProgram.getMemory();
                        byte[] doubleData = new byte[8];
                        int read_byte;
                        try {
                            read_byte = memory.getBytes(readPointer, doubleData);
                        } catch (MemoryAccessException e) {
                            continue;
                        }
                        String resultString = "";
                        if(read_byte==8){
                            ByteBuffer buffer = ByteBuffer.wrap(doubleData);
                            buffer.order(ByteOrder.LITTLE_ENDIAN);
                            double d = Double.longBitsToDouble(buffer.getLong());
                            resultString = "double: " + d + " ";
                        }
                        if(read_byte>=4){
                            ByteBuffer buffer = ByteBuffer.wrap(doubleData);
                            buffer.order(ByteOrder.LITTLE_ENDIAN);
                            float f = Float.intBitsToFloat(buffer.getInt());
                            resultString += "float: " + f;
                        }
                        result.put(primarySymbolName, resultString);
                    } else {
                        data = listing.getDefinedDataAt(target);
                        if (data != null && data.isDefined()) {
                            DataType dt = data.getDataType();
                            if (!(dt instanceof AbstractFloatDataType)) continue;
                            // 获取内容
                            Object value = data.getValue();
                            if (value instanceof Double) {
                                result.put(primarySymbolName, value.toString());
                            }
                        }
                    }
                }
            }
        }
        return result;
    }


    public static boolean isReferenceFunction(Function f, String name) {
        if (!GO) return false;
        var patten = Pattern.compile(Pattern.quote(f.getName())+"\\.(deferwrap|gowrap|func).*");
        return patten.matcher(name).matches();
    }

    public List<Function> getDeferWrapFunctions(Function f) {
        if (!GO) {
            return List.of();
        }
        ArrayList<Function> result = new ArrayList<>();
        for (var f1 : functionManager.getFunctions(true)) {
            if (isReferenceFunction(f, f1.getName())) {
                result.add(f1);
            }
        }
        return result;
    }

    public HashMap<String, String> getAllStructures() {
        HashMap<String, String> result = new HashMap<>();
        for (Iterator<Structure> it = dataTypeManager.getAllStructures(); it.hasNext() && !monitor.isCancelled(); ) {
            var struct = it.next();
            StringBuilder structStringBuilder = new StringBuilder();
            formatStructure(structStringBuilder, struct);
            result.put(struct.getName(), structStringBuilder.toString());

        }
        return result;
    }

    public HashMap<String, Long> getAllSymbols() {
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        SymbolIterator it = symbolTable.getAllSymbols(true);
        HashMap<String, Long> result = new HashMap<>();

        while (it.hasNext() && !monitor.isCancelled()) {
            Symbol symbol = it.next();
            Address addr = symbol.getAddress();
            if (!addr.isLoadedMemoryAddress()) continue;
            result.put(symbol.getName(), addr.getOffset());
        }
        return result;
    }

    public void handleFunction(Function f) throws CancelledException {
        println("process " + f.getName());
        // source code range
        List<String> sourceCodeRange = getSourceCodeRange(f);
        if (GO && (sourceCodeRange.isEmpty() || sourceCodeRange.getFirst().matches("^.*<autogenerated>.*$|^_cgo_gotypes\\.go:.*$") || !sourceCodeRange.getFirst().matches("^.*\\.[gG][oO]:[0-9]+$"))) {
            return;
        }
        StringBuilder sourceCodeRangeStringBuilder = new StringBuilder();
        for (var r : sourceCodeRange) {
            sourceCodeRangeStringBuilder.append(r).append("\n");
        }
        if(!sourceCodeRangeStringBuilder.isEmpty()) {
            sourceCodeRangeStringBuilder.deleteCharAt(sourceCodeRangeStringBuilder.length() - 1);
        }
        String sourceCodeRangeString = sourceCodeRangeStringBuilder.toString();

        var deferWrapFunctions = getDeferWrapFunctions(f);

        // 初始化反编译器
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(f.getProgram());
        DecompileResults decompileResults = decompiler.decompileFunction(f, 300, monitor);
        if (!decompileResults.decompileCompleted()) {
            if (!monitor.isCancelled()) printerr(f.getName() + "反编译失败：" + decompileResults.getErrorMessage());
            decompiler.dispose();
            return;
        }
        // 获取反编译代码
        String decompiledCode = formatDecompileCode(decompileResults);

        // 获取汇编代码
        HashMap<String, String> symbolMap = buildSymbolMap(f);
        StringBuilder asmBuilder = new StringBuilder();
        asmBuilder.append(f.getName()).append(":\n");
        formatAsm(asmBuilder, f, symbolMap);
        for (var defer : deferWrapFunctions) {
            asmBuilder.append("\n");
            asmBuilder.append(defer.getName()).append(":\n");
            formatAsm(asmBuilder, defer, buildSymbolMap(defer));
        }
        String asm = asmBuilder.toString();

        List<BasicBlockInfo> basicBlockInfos = formatBasicBlock(f, symbolMap);

        // 获取所有结构体
        List<Structure> baseStructureList = getStructuresUsedInFunction(decompileResults);
        for (var defer : deferWrapFunctions) {
            DecompInterface decompilerDefer = new DecompInterface();
            decompilerDefer.openProgram(f.getProgram());
            DecompileResults deferDecompileResults = decompilerDefer.decompileFunction(defer, 300, monitor);
            if (!deferDecompileResults.decompileCompleted()) {
                if (monitor.isCancelled()) return;
                printerr(defer.getName() + "反编译失败：" + decompileResults.getErrorMessage());
                decompilerDefer.dispose();
            }
            baseStructureList.addAll(getStructuresUsedInFunction(deferDecompileResults));
            decompilerDefer.dispose();
        }
        List<Structure> structs = getAllUsedStructures(baseStructureList);
        var structNameList = structs.stream().map(DataType::getName).toList();

        // 获取所有字符串
        HashMap<String, String> stringMap = getStringsUsedInFunction(f);
        for (var defer : deferWrapFunctions) {
            stringMap.putAll(getStringsUsedInFunction(defer));
        }
        for (var entry : stringMap.entrySet()) {
            Gson gson = new Gson();
            entry.setValue(gson.toJson(entry.getValue()));
        }

        // 获取所有浮点数
        HashMap<String, String> floatMap = getFloatsUsedInFunction(f);

        // 输出
        if (monitor.isCancelled()) return;
        saveFuncToDatabase(f.getName(), basicBlockInfos, asm, decompiledCode, sourceCodeRangeString, structNameList, stringMap, floatMap);
        decompiler.dispose();
    }

    public void saveFuncToDatabase(String name, List<BasicBlockInfo> basicBlockInfos, String asm, String decompiled_code, String source_code_range, List<String> structs, Map<String, String> strings, Map<String, String> floats) {
        functionCollection.insertOne(
            new Document()
                .append("_id", programId + "-" + name + "-" + optLevel)
                .append("optLevel", optLevel)
                .append("name", name)
                .append("asm", asm)
                .append("basicblocks", basicBlockInfos)
                .append("decompiled_code", decompiled_code)
                .append("source_code_range", source_code_range)
                .append("structs", structs)
                .append("strings", strings)
                .append("floats", floats)
                .append("binary", programId)
        );
    }

    public void getConnectionAndInit() {
        String uri;
        if (getScriptArgs().length <= 1) {
            uri = "mongodb://192.168.6.146:27017?connectTimeoutMS=2000";
        } else {
            uri = getScriptArgs()[1];
        }
        CodecProvider pojoCodecProvider = PojoCodecProvider.builder().automatic(true).build();
        CodecRegistry pojoCodecRegistry = CodecRegistries.fromRegistries(MongoClientSettings.getDefaultCodecRegistry(), CodecRegistries.fromProviders(pojoCodecProvider));
        mongoClient = MongoClients.create(uri);
        MongoDatabase database = mongoClient.getDatabase("decompile").withCodecRegistry(pojoCodecRegistry);
        functionCollection = database.getCollection("functions");

        // MongoCollection<Document> structsCollection = database.getCollection("structs");
        // structsCollection.deleteMany(new Document("binary", programId).toBsonDocument());
        // var structDocs = getAllStructures().entrySet().stream().map(entry ->
        //     new Document("_id", new ObjectId())
        //         .append("binary", programId)
        //         .append("name", entry.getKey())
        //         .append("value", entry.getValue())
        // ).toList();
        // structsCollection.insertMany(structDocs);

        // MongoCollection<Document> symbolsCollection = database.getCollection("symbols");
        // symbolsCollection.deleteMany(new Document("binary", programId).toBsonDocument());
        // var symbolsDocs = getAllSymbols().entrySet().stream().map(entry ->
        //     new Document("_id", new ObjectId())
        //         .append("binary", programId)
        //         .append("name", entry.getKey())
        //         .append("value", entry.getValue())
        // ).toList();
        // symbolsCollection.insertMany(symbolsDocs);
    }

    public void run() {
        programId = getScriptArgs().length != 0 ? getScriptArgs()[0] : "test";
        HashSet<String> functionList = null;
        if(programId.contains(",|||,")) {
            String[] splitList =programId.split(",\\|\\|\\|,");
            programId = splitList[0];
            optLevel = splitList[1];
            functionList = new HashSet<String>(splitList.length - 1);
            for(int i = 2; i< splitList.length; i++) {
                functionList.add(splitList[i]);
            }
        }

        analyzeAll(currentProgram);
        functionManager = currentProgram.getFunctionManager();
        symbolTable = currentProgram.getSymbolTable();
        dataTypeManager = currentProgram.getDataTypeManager();
        basicBlockModel = new BasicBlockModel(currentProgram);

        MemoryBlock textBlock = null;
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if(".text".equals(block.getName())) {
                textBlock = block;
                break;
            }
        }
        if(textBlock == null) {
            println(".text section not found");
            System.exit(1);
        }

        getConnectionAndInit();

        for (var f : functionManager.getFunctions(true)) {
            if (monitor.isCancelled()) break;
            if (!textBlock.contains(f.getBody().getMinAddress()) || !textBlock.contains(f.getBody().getMaxAddress())) continue;
            if (GO && f.getName().matches("^runtime[./].*$|^type:.*$|^internal/.*$|^reflect.*$|^context[./].*$|^x?_cgo.*$|^.*\\.deferwrap[0-9]+$|^.*\\.gowrap[0-9]+$|^.*\\.func[0-9].*$|^.*\\._C.*$"))
                continue;
            if (GO && !f.getName().contains(".") && !f.getName().contains("/") && !f.getName().contains("(")) continue;
            if (functionList != null && !functionList.contains(f.getName())) continue;
            if (functionCollection.countDocuments(new Document().append("_id", programId + "-" + f.getName())) != 0) {
                functionCollection.deleteOne(new Document().append("_id", programId + "-" + f.getName()));
            }
            try {
                handleFunction(f);
            } catch (CancelledException e) {
                throw new RuntimeException(e);
            }
        }
        mongoClient.close();
    }

    public static class BasicBlockEdge {
        public String edgeType;
        public String name;

        public BasicBlockEdge(String name, String edgeType) {
            this.name = name;
            this.edgeType = edgeType;
        }

        public BasicBlockEdge() {}

    }

    public static class BasicBlockInfo {
        public String id;
        public String content;
        public List<BasicBlockEdge> ins;
        public List<BasicBlockEdge> outs;

        public BasicBlockInfo() {}

    }
}

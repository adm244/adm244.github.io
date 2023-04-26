/*
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <http://unlicense.org/>
*/

using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using Summerloud.Extensions;

/* ======================================
          BINARYREADER EXTENSION
   ====================================== */

namespace Summerloud.Extensions
{
  public static class BinaryReaderExtension
  {
    public static string ReadCString(this BinaryReader reader)
    {
      if (reader.BaseStream.Position >= reader.BaseStream.Length)
        return string.Empty;

      StringBuilder stringBuilder = new StringBuilder();

      char c;
      while ((c = reader.ReadChar()) != 0) {
        stringBuilder.Append(c);
      }

      return stringBuilder.ToString();
    }

    public static string ReadString8(this BinaryReader reader)
    {
      if (reader.BaseStream.Position >= reader.BaseStream.Length)
        return string.Empty;

      int length = reader.ReadByte();
      char[] buffer = reader.ReadChars(length);

      for (length = 0; length < buffer.Length; ++length) {
        if (buffer[length] == '\0') {
          break;
        }
      }

      return new string(buffer, 0, length);
    }

    public static string ReadString8Xor44(this BinaryReader reader)
    {
      if (reader.BaseStream.Position >= reader.BaseStream.Length)
        return string.Empty;

      byte length = reader.ReadByte();
      byte[] buffer = reader.ReadBytes(length);

      for (int x = 0; x < buffer.Length; ++x) {
        buffer[x] ^= 0x44; // 'D'
      }

      for (length = 0; length < buffer.Length; ++length) {
        if (buffer[length] == '\0') {
          break;
        }
      }

      return Encoding.Latin1.GetString(buffer, 0, length);
    }
  }
}

/* ======================================
          BINARYWRITER EXTENSION
   ====================================== */

namespace Summerloud.Extensions
{
  public static class BinaryWriterExtension
  {
    public static void WriteCString(this BinaryWriter writer, string value)
    {
      writer.Write(value.ToCharArray());
      writer.Write((byte)0);
    }
  }
}

/* ======================================
              MAIN PROGRAM
   ====================================== */

namespace Summerloud
{
  internal class Program
  {
    public static void Main(string[] args)
    {
      if (args.Length < 1)
      {
        Console.WriteLine("ERROR: No filename provided!");
        return;
      }

      string filepath = args[0];

      // NOTE: Uncomment to extract dcp archive at filepath
      // ExtractPackageFile(filepath);

      // NOTE: Uncomment to disassemble script at filepath
      // Script script = Script.ReadFile(filepath);
      // ScriptDisas scriptDisas = script.Disassemble();
      // scriptDisas.WriteFile(filepath + ".asm");

      // NOTE: Uncomment to assemble script at filepath
      // ScriptAsm scriptAsm = ScriptAsm.ReadFile(filepath);
      // Script script = scriptAsm.Assemble();
      // script.WriteFile(filepath + ".script");
    }

    /* ======================================
                INSTRUCTIONS TABLE
       ====================================== */

    public static class VM
    {
      public static InstructionDefinition[] InstructionTable = {
        /* 0x00 */ new (Opcodes.II_DEF_VAR,         "DEF_VAR",        new[] { OperandType.Symbol }),
        /* 0x01 */ new (Opcodes.II_DEF_GLOB_VAR,    "DEF_GLOB_VAR",   new[] { OperandType.Symbol }),
        /* 0x02 */ new (Opcodes.II_RET,             "RET"                                         ),
        /* 0x03 */ new (Opcodes.II_RET_EVENT,       "RET_EVENT"                                   ),
        /* 0x04 */ new (Opcodes.II_CALL,            "CALL",           new[] { OperandType.Offset }),
        /* 0x05 */ new (Opcodes.II_CALL_BY_EXP,     "CALL_BY_EXP"                                 ),
        /* 0x06 */ new (Opcodes.II_EXTERNAL_CALL,   "EXTERNAL_CALL",  new[] { OperandType.Symbol }),
        /* 0x07 */ new (Opcodes.II_SCOPE,           "SCOPE"                                       ),
        /* 0x08 */ new (Opcodes.II_CORRECT_STACK,   "CORRECT_STACK",  new[] { OperandType.Integer }),
        /* 0x09 */ new (Opcodes.II_CREATE_OBJECT,   "CREATE_OBJECT"                               ),
        /* 0x0A */ new (Opcodes.II_POP_EMPTY,       "POP_EMPTY"                                   ),
        /* 0x0B */ new (Opcodes.II_PUSH_VAR,        "PUSH_VAR",       new[] { OperandType.Symbol }),
        /* 0x0C */ new (Opcodes.II_PUSH_VAR_REF,    "PUSH_VAR_REF",   new[] { OperandType.Symbol }),
        /* 0x0D */ new (Opcodes.II_POP_VAR,         "POP_VAR",        new[] { OperandType.Symbol }),
        /* 0x0E */ new (Opcodes.II_PUSH_VAR_THIS,   "PUSH_VAR_THIS"                               ),
        /* 0x0F */ new (Opcodes.II_PUSH_INT,        "PUSH_INT",       new[] { OperandType.Integer }),
        /* 0x10 */ new (Opcodes.II_PUSH_BOOL,       "PUSH_BOOL",      new[] { OperandType.Integer }),
        /* 0x11 */ new (Opcodes.II_PUSH_FLOAT,      "PUSH_FLOAT",     new[] { OperandType.Double }),
        /* 0x12 */ new (Opcodes.II_PUSH_STRING,     "PUSH_STRING",    new[] { OperandType.String }),
        /* 0x13 */ new (Opcodes.II_PUSH_NULL,       "PUSH_NULL"                                   ),
        /* 0x14 */ new (Opcodes.II_PUSH_THIS_FROM_STACK, "PUSH_THIS_FROM_STACK"                   ),
        /* 0x15 */ new (Opcodes.II_PUSH_THIS,       "PUSH_THIS",      new[] { OperandType.Symbol }),
        /* 0x16 */ new (Opcodes.II_POP_THIS,        "POP_THIS"                                    ),
        /* 0x17 */ new (Opcodes.II_PUSH_BY_EXP,     "PUSH_BY_EXP"                                 ),
        /* 0x18 */ new (Opcodes.II_POP_BY_EXP,      "POP_BY_EXP"                                  ),
        /* 0x19 */ new (Opcodes.II_JMP,             "JMP",            new[] { OperandType.Offset }),
        /* 0x1A */ new (Opcodes.II_JMP_FALSE,       "JMP_FALSE",      new[] { OperandType.Offset }),
        /* 0x1B */ new (Opcodes.II_ADD,             "ADD"                                         ),
        /* 0x1C */ new (Opcodes.II_SUB,             "SUB"                                         ),
        /* 0x1D */ new (Opcodes.II_MUL,             "MUL"                                         ),
        /* 0x1E */ new (Opcodes.II_DIV,             "DIV"                                         ),
        /* 0x1F */ new (Opcodes.II_MODULO,          "MODULO"                                      ),
        /* 0x20 */ new (Opcodes.II_NOT,             "NOT"                                         ),
        /* 0x21 */ new (Opcodes.II_AND,             "AND"                                         ),
        /* 0x22 */ new (Opcodes.II_OR,              "OR"                                          ),
        /* 0x23 */ new (Opcodes.II_CMP_EQ,          "CMP_EQ"                                      ),
        /* 0x24 */ new (Opcodes.II_CMP_NE,          "CMP_NE"                                      ),
        /* 0x25 */ new (Opcodes.II_CMP_L,           "CMP_L"                                       ),
        /* 0x26 */ new (Opcodes.II_CMP_G,           "CMP_G"                                       ),
        /* 0x27 */ new (Opcodes.II_CMP_LE,          "CMP_LE"                                      ),
        /* 0x28 */ new (Opcodes.II_CMP_GE,          "CMP_GE"                                      ),
        /* 0x29 */ new (Opcodes.II_CMP_STRICT_EQ,   "CMP_STRICT_EQ"                               ),
        /* 0x2A */ new (Opcodes.II_CMP_STRICT_NE,   "CMP_STRICT_NE"                               ),
        /* 0x2B */ new (Opcodes.II_DBG_LINE,        "DBG_LINE",       new[] { OperandType.Integer }),
        /* 0x2C */ new (Opcodes.II_POP_REG1,        "POP_REG1"                                    ),
        /* 0x2D */ new (Opcodes.II_PUSH_REG1,       "PUSH_REG1"                                   ),
        /* 0x2E */ new (Opcodes.II_DEF_CONST_VAR,   "DEF_CONST_VAR",  new[] { OperandType.Symbol }),
      };
    }

    public enum Opcodes
    {
      II_DEF_VAR = 0,
      II_DEF_GLOB_VAR,
      II_RET,
      II_RET_EVENT,
      II_CALL,
      II_CALL_BY_EXP,
      II_EXTERNAL_CALL,
      II_SCOPE,
      II_CORRECT_STACK,
      II_CREATE_OBJECT,
      II_POP_EMPTY,
      II_PUSH_VAR,
      II_PUSH_VAR_REF,
      II_POP_VAR,
      II_PUSH_VAR_THIS, // push current this on stack
      II_PUSH_INT,
      II_PUSH_BOOL,
      II_PUSH_FLOAT,
      II_PUSH_STRING,
      II_PUSH_NULL,
      II_PUSH_THIS_FROM_STACK,
      II_PUSH_THIS,
      II_POP_THIS,
      II_PUSH_BY_EXP,
      II_POP_BY_EXP,
      II_JMP,
      II_JMP_FALSE,
      II_ADD,
      II_SUB,
      II_MUL,
      II_DIV,
      II_MODULO,
      II_NOT,
      II_AND,
      II_OR,
      II_CMP_EQ,
      II_CMP_NE,
      II_CMP_L,
      II_CMP_G,
      II_CMP_LE,
      II_CMP_GE,
      II_CMP_STRICT_EQ,
      II_CMP_STRICT_NE,
      II_DBG_LINE,
      II_POP_REG1,
      II_PUSH_REG1,
      II_DEF_CONST_VAR
    }

    public struct InstructionDefinition
    {
      public Opcodes Opcode;
      public string Mnemonic;
      public OperandType[] Operands = Array.Empty<OperandType>();

      public InstructionDefinition(Opcodes opcode, string mnemonic, params OperandType[] operands)
      {
        Opcode = opcode;
        Mnemonic = mnemonic;

        if (operands != null)
        {
          Operands = operands;
        }
      }
    }

    /* ======================================
                  SCRIPT OBJECT
       ====================================== */

    public class Script
    {
      private const int HeaderSize = 32;

      public const uint Magic = 0xDEC0ADDE;
      public const uint Version101 = 0x0101;
      public const uint Version102 = 0x0102;

      public string Filename;
      public uint Version;
      public long CodeOffset;

      public byte[] Code;
      public string[] Symbols;
      public SymbolPos[] Functions;
      public SymbolPos[] Events;
      public ExternalFunction[] Externals;
      public SymbolPos[] Methods;

      private Script()
        : this(string.Empty)
      {
      }

      public Script(string filename)
      {
        Filename = filename;
        Version = Version102;
        CodeOffset = HeaderSize + Filename.Length + 1;

        Code = Array.Empty<byte>();
        Symbols = Array.Empty<string>();
        Functions = Array.Empty<SymbolPos>();
        Events = Array.Empty<SymbolPos>();
        Externals = Array.Empty<ExternalFunction>();
        Methods = Array.Empty<SymbolPos>();
      }

      public static Script ReadFile(string filepath)
      {
        Script script = new Script();

        using FileStream fileStream = new FileStream(filepath, FileMode.Open, FileAccess.Read);
        using BinaryReader reader = new BinaryReader(fileStream);

        uint magic = reader.ReadUInt32();
        if (magic != Magic)
        {
          throw new InvalidDataException($"ERROR: Invalid script magic: {magic:X}!");
        }

        script.Version = reader.ReadUInt32();
        if (script.Version != Version102)
        {
          throw new InvalidDataException($"ERROR: Version is not supported: {script.Version:X}!");
        }

        uint codeOffset = reader.ReadUInt32();
        uint funcTableOffset = reader.ReadUInt32();
        uint symbolTableOffset = reader.ReadUInt32();
        uint eventTableOffset = reader.ReadUInt32();
        uint externalsTableOffset = reader.ReadUInt32();
        uint methodTableOffset = reader.ReadUInt32();

        script.CodeOffset = codeOffset;
        script.Filename = reader.ReadCString();

        // Read code section
        reader.BaseStream.Position = codeOffset;
        // FIXME(adm244): find another way to get code section size (this may be incorrect if sections are in different order)
        int codeSize = (int)(funcTableOffset - codeOffset);
        script.Code = reader.ReadBytes(codeSize);

        // Read symbols table
        reader.BaseStream.Position = symbolTableOffset;
        uint symbolsCount = reader.ReadUInt32();
        script.Symbols = new String[symbolsCount];
        for (int i = 0; i < symbolsCount; ++i)
        {
          int index = reader.ReadInt32();
          script.Symbols[index] = reader.ReadCString();
        }

        // Read functions table
        reader.BaseStream.Position = funcTableOffset;
        uint funcCount = reader.ReadUInt32();
        script.Functions = new SymbolPos[funcCount];
        for (int i = 0; i < script.Functions.Length; ++i)
        {
          script.Functions[i].Position = reader.ReadUInt32() - codeOffset;
          script.Functions[i].Name = reader.ReadCString();
        }

        // Read events table
        reader.BaseStream.Position = eventTableOffset;
        uint eventsCount = reader.ReadUInt32();
        script.Events = new SymbolPos[eventsCount];
        for (int i = 0; i < script.Events.Length; ++i)
        {
          script.Events[i].Position = reader.ReadUInt32() - codeOffset;
          script.Events[i].Name = reader.ReadCString();
        }

        if (script.Version >= Version101)
        {
          // Read externals table
          reader.BaseStream.Position = externalsTableOffset;
          uint externalsCount = reader.ReadUInt32();
          script.Externals = new ExternalFunction[externalsCount];
          for (int i = 0; i < script.Externals.Length; ++i)
          {
            script.Externals[i].DllName = reader.ReadCString();
            script.Externals[i].Name = reader.ReadCString();
            script.Externals[i].Type = (CallType)reader.ReadInt32();
            script.Externals[i].ReturnType = (ExternalType)reader.ReadInt32();

            uint paramsCount = reader.ReadUInt32();
            script.Externals[i].Params = new ExternalType[paramsCount];
            for (int p = 0; p < paramsCount; ++p)
            {
              script.Externals[i].Params[p] = (ExternalType)reader.ReadInt32();
            }
          }
        }

        // Read methods table
        reader.BaseStream.Position = methodTableOffset;
        uint methodsCount = reader.ReadUInt32();
        script.Methods = new SymbolPos[methodsCount];
        for (int i = 0; i < script.Methods.Length; ++i)
        {
          script.Methods[i].Position = reader.ReadUInt32() - codeOffset;
          script.Methods[i].Name = reader.ReadCString();
        }

        return script;
      }

      public void WriteFile(string filename)
      {
        using FileStream stream = new FileStream(filename, FileMode.Create, FileAccess.Write);
        using BinaryWriter writer = new BinaryWriter(stream, Encoding.Latin1);

        writer.Write((UInt32)Magic);
        writer.Write((UInt32)Version);
        writer.Write((UInt32)CodeOffset);
        writer.Write((UInt32)0); // functions table
        writer.Write((UInt32)0); // symbols table
        writer.Write((UInt32)0); // events table
        writer.Write((UInt32)0); // externals table
        writer.Write((UInt32)0); // methods table

        writer.WriteCString(Filename);

        if (writer.BaseStream.Position != CodeOffset)
          throw new ArgumentException(
            $"Invalid code offset (expected: 0x{CodeOffset:X8}"
            + $", got: 0x{writer.BaseStream.Position:X8})");

        writer.Write((byte[])Code);

        long functionsOffset = writer.BaseStream.Position;
        writer.Write((UInt32)Functions.Length);
        for (int i = 0; i < Functions.Length; ++i)
        {
          writer.Write((UInt32)(Functions[i].Position + CodeOffset));
          writer.WriteCString(Functions[i].Name);
        }

        long symbolsOffset = writer.BaseStream.Position;
        writer.Write((UInt32)Symbols.Length);
        for (int i = 0; i < Symbols.Length; ++i)
        {
          writer.Write((Int32)i);
          writer.WriteCString(Symbols[i]);
        }

        long eventsOffset = writer.BaseStream.Position;
        writer.Write((UInt32)Events.Length);
        for (int i = 0; i < Events.Length; ++i)
        {
          writer.Write((UInt32)(Events[i].Position + CodeOffset));
          writer.WriteCString(Events[i].Name);
        }

        long externalsOffset = writer.BaseStream.Position;
        if (Version >= Version101)
        {
          writer.Write((UInt32)Externals.Length);
          for (int i = 0; i < Externals.Length; ++i)
          {
            writer.WriteCString(Externals[i].DllName);
            writer.WriteCString(Externals[i].Name);
            writer.Write((Int32)Externals[i].Type);
            writer.Write((Int32)Externals[i].ReturnType);

            writer.Write((UInt32)Externals[i].Params.Length);
            for (int k = 0; k < Externals[i].Params.Length; ++k)
            {
              writer.Write((Int32)Externals[i].Params[k]);
            }
          }
        }

        long methodsOffset = writer.BaseStream.Position;
        writer.Write((UInt32)Methods.Length);
        for (int i = 0; i < Methods.Length; ++i)
        {
          writer.Write((UInt32)(Methods[i].Position + CodeOffset));
          writer.WriteCString(Methods[i].Name);
        }

        writer.BaseStream.Position = 0x0C;
        writer.Write((UInt32)functionsOffset);

        writer.BaseStream.Position = 0x10;
        writer.Write((UInt32)symbolsOffset);

        writer.BaseStream.Position = 0x14;
        writer.Write((UInt32)eventsOffset);

        if (Version >= Version101)
        {
          writer.BaseStream.Position = 0x18;
          writer.Write((UInt32)externalsOffset);
        }

        writer.BaseStream.Position = 0x1C;
        writer.Write((UInt32)methodsOffset);
      }

      public ScriptDisas Disassemble()
      {
        List<Instruction> instructions = new List<Instruction>();
        List<AddressReference> references = new List<AddressReference>();
        List<EntryPoint> entryPoints = new List<EntryPoint>();

        entryPoints.AddRange(SymbolsToEntryPoints(EntryPointType.Function, Functions));
        entryPoints.AddRange(SymbolsToEntryPoints(EntryPointType.Event, Events));
        entryPoints.AddRange(SymbolsToEntryPoints(EntryPointType.Method, Methods));

        using MemoryStream stream = new MemoryStream(Code);
        using BinaryReader reader = new BinaryReader(stream, Encoding.Latin1);

        while (stream.Position < stream.Length)
        {
          long address = stream.Position;
          int opcode = reader.ReadInt32();

          if (opcode < 0 || opcode > VM.InstructionTable.Length)
          {
            throw new InvalidDataException($"Unknown opcode: {opcode}");
          }

          InstructionDefinition instrDef = VM.InstructionTable[opcode];
          Operand[] operands = ReadOperands(reader, instrDef);
          for (int i = 0; i < operands.Length; ++i)
          {
            if (operands[i].Type == OperandType.Offset)
            {
              references.Add(new AddressReference(address, operands[i].PtrVal));
            }
          }

          instructions.Add(new Instruction(address, (Opcodes)opcode, operands));
        }

        return new ScriptDisas(Filename, Externals, Symbols, entryPoints, references, instructions);
      }

      private IEnumerable<EntryPoint> SymbolsToEntryPoints(EntryPointType type, SymbolPos[] symbols)
      {
        EntryPoint[] entryPoints = new EntryPoint[symbols.Length];

        for (int i = 0; i < symbols.Length; ++i)
        {
          entryPoints[i] = new EntryPoint(type, symbols[i].Name, symbols[i].Position);
        }

        return entryPoints;
      }

      private Operand[] ReadOperands(BinaryReader reader, InstructionDefinition instrDef)
      {
        List<Operand> operands = new List<Operand>();

        for (int i = 0; i < instrDef.Operands.Length; ++i)
        {
          OperandType operandType = instrDef.Operands[i];
          Operand operand = new Operand(operandType);

          switch (operandType)
          {
            case OperandType.Symbol:
              {
                operand.StrVal = GetSymbol(reader.ReadInt32());
                break;
              }

            case OperandType.Offset:
              {
                operand.PtrVal = reader.ReadUInt32() - CodeOffset;
                break;
              }

            case OperandType.Integer:
              {
                operand.IntVal = reader.ReadInt32();
                break;
              }

            case OperandType.Double:
              {
                operand.DoubleVal = reader.ReadDouble();
                break;
              }

            case OperandType.String:
              {
                operand.StrVal = reader.ReadCString().Replace("\"", "\\\"");
                break;
              }

            default:
              throw new InvalidDataException($"Invalid operand type: {operandType}");
          }

          operands.Add(operand);
        }

        return operands.ToArray();
      }

      private string GetSymbol(int index)
      {
        if (Symbols == null)
        {
          throw new InvalidDataException("Symbols table is uninitialized");
        }

        if (Symbols.Length == 0)
        {
          throw new InvalidDataException("Symbols table is empty");
        }

        if (index < 0 || index >= Symbols.Length)
        {
          throw new InvalidDataException($"Invalid symbol index: {index}");
        }

        return Symbols[index];
      }
    }

    public enum CallType
    {
      STDCALL = 0,
      CDECL,
      THISCALL
    }

    public enum ExternalType
    {
      VOID = 0,
      BOOL,
      LONG,
      BYTE,
      STRING,
      FLOAT,
      DOUBLE,
      MEMBUFFER
    }

    public struct ExternalFunction
    {
      public string Name;
      public string DllName;
      public CallType Type;
      public ExternalType ReturnType;
      public ExternalType[] Params;
    }

    public struct SymbolPos
    {
      public string Name;
      public long Position;

      public SymbolPos()
      {
        Name = string.Empty;
        Position = 0;
      }

      public SymbolPos(string name, long position)
      {
        Name = name;
        Position = position;
      }
    }

    /* ======================================
                DISASSEMBLED SCRIPT
       ====================================== */

    public struct ScriptDisas
    {
      public string Filepath;
      public ExternalFunction[] Externals;
      public string[] Symbols;
      public Dictionary<long, EntryPoint> EntryPoints;
      public Dictionary<long, List<AddressReference>> References;
      public Instruction[] Instructions;

      public ScriptDisas(string filepath, ICollection<ExternalFunction> externals,
        ICollection<string> symbols, ICollection<EntryPoint> entryPoints,
        ICollection<AddressReference> references, ICollection<Instruction> instructions)
      {
        Filepath = filepath;
        Externals = externals.ToArray();
        Symbols = symbols.ToArray();
        Instructions = instructions.ToArray();

        EntryPoints = new Dictionary<long, EntryPoint>(entryPoints.Count);
        foreach (var entryPoint in entryPoints)
        {
          EntryPoints.Add(entryPoint.Offset, entryPoint);
        }

        References = new Dictionary<long, List<AddressReference>>(references.Count);
        foreach (var reference in references)
        {
          if (References.TryGetValue(reference.OffsetTo, out List<AddressReference>? refs))
          {
            refs.Add(reference);
          }
          else
          {
            References.Add(reference.OffsetTo, new List<AddressReference>() { reference });
          }
        }
      }

      public void WriteFile(string filename)
      {
        using FileStream fileStream = new FileStream(filename, FileMode.Create, FileAccess.Write);
        using StreamWriter fileWriter = new StreamWriter(fileStream, Encoding.Latin1);

        WriteInfoSection(fileWriter);
        WriteExternalSection(fileWriter);
        WriteTextSection(fileWriter);
      }

      private void WriteInfoSection(StreamWriter writer)
      {
        writer.WriteLine(".info");
        writer.WriteLine(Filepath);
        writer.WriteLine();
      }

      private void WriteExternalSection(StreamWriter writer)
      {
        writer.WriteLine(".external");

        for (int i = 0; i < Externals.Length; ++i)
        {
          ExternalFunction e = Externals[i];
          writer.Write($"{e.DllName}:{e.Name}:{e.Type}:{e.ReturnType}:[");
          for (int arg = 0; arg < e.Params.Length; ++arg)
          {
            if (arg > 0)
            {
              writer.Write(",");
            }
            writer.Write($"{e.Params[arg]}");
          }
          writer.WriteLine("]");
        }

        writer.WriteLine();
      }

      private void WriteTextSection(StreamWriter writer)
      {
        writer.WriteLine(".text");

        for (int i = 0; i < Instructions.Length; ++i)
        {
          Instruction instr = Instructions[i];

          if (EntryPoints.TryGetValue(instr.Address, out EntryPoint entryPoint))
          {
            WriteReference(writer, instr.Address, $"{entryPoint.TypeName} {entryPoint.Name}:");
          }
          else if (References.ContainsKey(instr.Address))
          {
            WriteReference(writer, instr.Address, $"label{instr.Address:X8}:");
          }
          else if (instr.Opcode == Opcodes.II_DBG_LINE && i > 0)
          {
            writer.WriteLine();
          }

          writer.Write($"/* {instr.Address:X8} */");
          writer.Write($"{string.Empty.PadRight(4)}{instr.Mnemonic}");
          for (int k = 0; k < instr.Operands.Length; ++k)
          {
            WriteOperand(writer, instr.Operands[k]);
          }
          writer.WriteLine();
        }
      }

      private void WriteReference(StreamWriter writer, long address, string text)
      {
        writer.WriteLine();
        writer.Write(text);

        string refCountString = GetReferenceCountString(address);
        if (!string.IsNullOrWhiteSpace(refCountString))
        {
          writer.Write($" ; {refCountString}");
        }

        writer.WriteLine();
      }

      private string GetReferenceCountString(long address)
      {
        if (References.TryGetValue(address, out List<AddressReference>? refs))
        {
          string text = refs.Count == 1 ? "reference" : "references";
          return $"{refs.Count} {text}";
        }

        return string.Empty;
      }

      private void WriteOperand(StreamWriter writer, Operand operand)
      {
        if (operand.Type == OperandType.Offset)
        {
          if (EntryPoints.TryGetValue(operand.PtrVal, out EntryPoint entryPoint))
          {
            writer.Write($" {entryPoint.Name}");
          }
          else
          {
            writer.Write($" label{operand.ToString()}");
          }
        }
        else
        {
          writer.Write($" {operand.ToString()}");
        }
      }
    }

    public enum EntryPointType
    {
      Function,
      Event,
      Method
    }

    public enum OperandType
    {
      Symbol,
      Offset,
      Integer,
      Double,
      String
    }

    public struct Instruction
    {
      public long Address;
      public Opcodes Opcode;
      public Operand[] Operands;

      public Instruction(long address, Opcodes opcode, Operand[] operands)
      {
        Address = address;
        Opcode = opcode;
        Operands = operands;
      }

      public string Mnemonic => VM.InstructionTable[(int)Opcode].Mnemonic;
    }

    public struct AddressReference
    {
      public long OffsetFrom;
      public long OffsetTo;

      public AddressReference(long offsetFrom, long offsetTo)
      {
        OffsetFrom = offsetFrom;
        OffsetTo = offsetTo;
      }
    }

    public struct EntryPoint
    {
      public EntryPointType Type;
      public string Name;
      public long Offset;

      public EntryPoint(EntryPointType type, string name, long offset)
      {
        Type = type;
        Name = name;
        Offset = offset;
      }

      public string TypeName
      {
        get
        {
          switch (Type)
          {
            case EntryPointType.Function:
              return "function";
            case EntryPointType.Event:
              return "on";
            case EntryPointType.Method:
              return "method";

            default:
              throw new ArgumentException($"Invalid entry point type: {Type}");
          }
        }
      }
    }

    public struct Operand
    {
      public OperandType Type;
      public long PtrVal;
      public int IntVal;
      public double DoubleVal;
      public string StrVal;

      public Operand(OperandType type)
      {
        Type = type;
        PtrVal = 0;
        IntVal = 0;
        DoubleVal = 0;
        StrVal = string.Empty;
      }

      public override string ToString()
      {
        switch (Type)
        {
          case OperandType.Symbol:
          case OperandType.String:
            return $"\"{StrVal}\"";

          case OperandType.Offset:
            return $"{PtrVal:X8}";

          case OperandType.Integer:
            return $"{IntVal}";

          case OperandType.Double:
            return $"{DoubleVal}";

          default:
            throw new ArgumentException($"Invalid operand type: {Type}");
        }
      }
    }

    /* ======================================
                  ASSEMBLED SCRIPT
       ====================================== */

    public struct ScriptAsm
    {
      public string Filepath;
      public Dictionary<string, ExternalFunction> Externals;
      public Dictionary<int, string> References;
      public Dictionary<int, EntryPointAsm> EntryPoints;
      public List<InstructionAsm> Instructions;

      public ScriptAsm()
      {
        Filepath = string.Empty;
        Externals = new Dictionary<string, ExternalFunction>();
        References = new Dictionary<int, string>();
        EntryPoints = new Dictionary<int, EntryPointAsm>();
        Instructions = new List<InstructionAsm>();
      }

      public Script Assemble()
      {
        Script script = new Script(Filepath);
        Assembler assembler = new Assembler(script);

        script.Code = assembler.Assemble(this);
        script.Externals = Externals.Values.ToArray();
        script.Symbols = assembler.Symbols.ToArray();
        script.Functions = assembler.Functions.ToArray();
        script.Events = assembler.Events.ToArray();
        script.Methods = assembler.Methods.ToArray();

        return script;
      }

      public static ScriptAsm ReadFile(string filename)
      {
        ScriptAsm scriptAsm = new ScriptAsm();

        using FileStream stream = new FileStream(filename, FileMode.Open, FileAccess.Read);
        using StreamReader reader = new StreamReader(stream, Encoding.Latin1);

        AssemblySection section = AssemblySection.Info;
        while (!reader.EndOfStream)
        {
          string line = reader.ReadLine()?.Trim() ?? string.Empty;
          if (string.IsNullOrEmpty(line) || line.StartsWith(';'))
            continue;

          if (line == ".info")
            section = AssemblySection.Info;
          else if (line == ".external")
            section = AssemblySection.External;
          else if (line == ".text")
            section = AssemblySection.Text;
          else
            scriptAsm.ReadAsSection(line, section);
        }

        if (string.IsNullOrEmpty(scriptAsm.Filepath))
          scriptAsm.Filepath = Path.GetFileNameWithoutExtension(filename);

        return scriptAsm;
      }

      private void ReadAsSection(string line, AssemblySection section)
      {
        switch (section)
        {
          case AssemblySection.Info:
            ReadAsInfoSection(line);
            break;

          case AssemblySection.External:
            ReadAsExternalSection(line);
            break;

          case AssemblySection.Text:
            ReadAsTextSection(line);
            break;

          default:
            throw new ArgumentException($"Invalid section type: {section}");
        }
      }

      private void ReadAsInfoSection(string line)
      {
        if (!string.IsNullOrEmpty(Filepath))
          throw new InvalidDataException("Invalid info section format");

        Filepath = line;
      }

      private void ReadAsExternalSection(string line)
      {
        string[] parts = line.Split(':', StringSplitOptions.RemoveEmptyEntries
                                       | StringSplitOptions.TrimEntries);
        if (parts.Length != 5)
          throw new InvalidDataException("Invalid external entry format");

        ExternalFunction external = new ExternalFunction
        {
          DllName = parts[0],
          Name = parts[1],
          Type = Enum.Parse<CallType>(parts[2], ignoreCase: true),
          ReturnType = Enum.Parse<ExternalType>(parts[3], ignoreCase: true),
          Params = ParseExternalParams(parts[4])
        };

        if (!Externals.ContainsKey(external.Name))
          Externals.Add(external.Name, external);
      }

      private ExternalType[] ParseExternalParams(string str)
      {
        if (!str.StartsWith('[') || !str.EndsWith(']'))
          throw new InvalidDataException("Invalid external params format");

        string[] parts = str.Substring(1, str.Length - 2).Split(',',
          StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        return parts.Select(p => Enum.Parse<ExternalType>(p, ignoreCase: true))
                    .ToArray();
      }

      private void ReadAsTextSection(string line)
      {
        if (line.Contains(':'))
          ReadTextReference(line);
        else
          ReadTextInstruction(line);
      }

      private void ReadTextReference(string line)
      {
        if (line.StartsWith("label"))
          ReadTextLabel(line);
        else
          ReadTextEntryPoint(line);
      }

      private void ReadTextLabel(string line)
      {
        string refName = line.Substring(0, line.IndexOf(':'));
        if (refName.Split(' ').Length > 1)
          throw new InvalidDataException("Invalid label format");

        References.Add(Instructions.Count, refName);
      }

      private void ReadTextEntryPoint(string line)
      {
        string[] parts = line.Substring(0, line.IndexOf(':')).Split(' ',
          StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length != 2)
          throw new InvalidDataException("Invalid entry point format");

        EntryPointAsm entryPoint = new EntryPointAsm
        {
          Type = Enum.Parse<EntryPointType>(parts[0], ignoreCase: true),
          Name = parts[1],
          Index = Instructions.Count
        };

        EntryPoints.Add(entryPoint.Index, entryPoint);
      }

      private void ReadTextInstruction(string line)
      {
        if (line.StartsWith("/*"))
        {
          int pos = line.LastIndexOf("*/");
          if (pos < 0)
            throw new InvalidDataException("Invalid address comment format");

          line = line.Substring(pos + 2).TrimStart();
        }

        string[] parts = line.Split(' ', 2, StringSplitOptions.TrimEntries);
        if (parts.Length < 1)
          throw new InvalidDataException("Invalid instruction line format");

        string mnemonic = parts[0];
        string argsStr = parts.Length == 2 ? parts[1] : string.Empty;

        InstructionDefinition instrDef = VM.InstructionTable.Single(
          instr => instr.Mnemonic == mnemonic
        );

        string[] args = ParseArguments(argsStr);
        if (args.Length != instrDef.Operands.Length)
          throw new InvalidDataException("Invalid instruction operands count");

        InstructionAsm instr = new InstructionAsm
        {
          Opcode = instrDef.Opcode,
          Operands = ReadOperands(instrDef, args)
        };

        Instructions.Add(instr);
      }

      private string[] ParseArguments(string line)
      {
        List<string> args = new List<string>();

        while (!string.IsNullOrEmpty(line))
        {
          string arg = line;

          if (line.StartsWith('\"'))
          {
            arg = ParseString(line);
            line = line.Substring(arg.Length + 2).TrimStart();
          }
          else
          {
            int pos = line.IndexOf(' ');
            if (pos > 0)
              arg = line.Substring(0, pos);

            line = line.Substring(arg.Length).TrimStart();
          }

          args.Add(arg);
        }

        return args.ToArray();
      }

      private string ParseString(string str)
      {
        for (int i = 1; i < str.Length; ++i)
        {
          if (str[i] == '\"' && str[i - 1] != '\\')
            return str.Substring(1, i - 1);
        }

        throw new InvalidDataException("Invalid string format");
      }

      private OperandAsm[] ReadOperands(InstructionDefinition instrDef, string[] args)
      {
        OperandAsm[] operands = new OperandAsm[instrDef.Operands.Length];

        for (int i = 0; i < instrDef.Operands.Length; ++i)
        {
          operands[i] = ReadOperand(instrDef.Operands[i], args[i]);
        }

        return operands;
      }

      private OperandAsm ReadOperand(OperandType type, string value)
      {
        switch (type)
        {
          case OperandType.Integer:
            return OperandAsm.CreateInteger(int.Parse(value));

          case OperandType.Double:
            return OperandAsm.CreateDouble(double.Parse(value));

          case OperandType.String:
            return OperandAsm.CreateString(value.Replace("\\\"", "\""));

          case OperandType.Symbol:
            return OperandAsm.CreateSymbol(value);

          case OperandType.Offset:
            return OperandAsm.CreateReference(value);

          default:
            throw new ArgumentException($"Invalid operand type: {type}");
        }
      }
    }

    public enum AssemblySection
    {
      Info,
      External,
      Text
    }

    public enum OperandAsmType
    {
      Integer,
      Double,
      String,
      Symbol,
      Reference
    }

    public struct Assembler
    {
      public Script Script;
      public List<string> Symbols;
      public Dictionary<string, long> Resolved;
      public List<UnresolvedReference> Unresolved;
      public List<long> Reallocs;

      public List<SymbolPos> Functions;
      public List<SymbolPos> Events;
      public List<SymbolPos> Methods;

      public Assembler(Script script)
      {
        Script = script;
        Symbols = new List<string>();
        Resolved = new Dictionary<string, long>();
        Unresolved = new List<UnresolvedReference>();
        Reallocs = new List<long>();

        Functions = new List<SymbolPos>();
        Events = new List<SymbolPos>();
        Methods = new List<SymbolPos>();
      }

      public byte[] Assemble(ScriptAsm scriptAsm)
      {
        using MemoryStream stream = new MemoryStream();
        using BinaryWriter writer = new BinaryWriter(stream, Encoding.Latin1);

        // Write header padding, so that all relative offsets are correct
        byte[] padding = new byte[Script.CodeOffset];
        writer.Write(padding);

        for (int i = 0; i < scriptAsm.Instructions.Count; ++i)
        {
          // TODO: merge References and EntryPoints collections into one

          if (scriptAsm.EntryPoints.TryGetValue(i, out EntryPointAsm entry))
          {
            long position = writer.BaseStream.Position;
            long positionOffset = position - Script.CodeOffset;

            switch (entry.Type)
            {
              case EntryPointType.Function:
                Functions.Add(new SymbolPos(entry.Name, positionOffset));
                break;

              case EntryPointType.Event:
                Events.Add(new SymbolPos(entry.Name, positionOffset));
                break;

              case EntryPointType.Method:
                Methods.Add(new SymbolPos(entry.Name, positionOffset));
                break;

              default:
                throw new ArgumentException($"Invalid entry point type: {entry.Type}");
            }

            Resolved.Add(entry.Name, position);
          }

          if (scriptAsm.References.TryGetValue(i, out string? refName))
            Resolved.Add(refName, writer.BaseStream.Position);

          AssembleInstruction(writer, scriptAsm.Instructions[i]);
        }

        // Try to resolve previously unresolved references
        foreach (var reference in Unresolved)
        {
          if (!Resolved.TryGetValue(reference.Name, out long offset))
            throw new InvalidDataException($"Undefined reference to: {reference.Name}");

          writer.BaseStream.Position = reference.Offset;
          writer.Write((UInt32)offset);
        }

        return stream.ToArray()
          .Skip(padding.Length)
          .ToArray();
      }

      private void AssembleInstruction(BinaryWriter writer, InstructionAsm instr)
      {
        writer.Write((Int32)instr.Opcode);
        for (int i = 0; i < instr.Operands.Length; ++i)
        {
          OperandAsm operand = instr.Operands[i];
          switch (operand.Type)
          {
            case OperandAsmType.Integer:
              writer.Write(operand.IntVal);
              break;

            case OperandAsmType.Double:
              writer.Write(operand.DoubleVal);
              break;

            case OperandAsmType.String:
              writer.WriteCString(operand.StrVal);
              break;

            case OperandAsmType.Symbol:
              {
                if (!Symbols.Contains(operand.StrVal))
                  Symbols.Add(operand.StrVal);

                writer.Write((Int32)Symbols.IndexOf(operand.StrVal));
                break;
              }

            case OperandAsmType.Reference:
              {
                Reallocs.Add(writer.BaseStream.Position);

                if (Resolved.TryGetValue(operand.RefName, out long offset))
                {
                  writer.Write((UInt32)offset);
                }
                else
                {
                  Unresolved.Add(new UnresolvedReference
                  {
                    Name = operand.RefName,
                    Offset = writer.BaseStream.Position
                  });
                  writer.Write((UInt32)0);
                }
                break;
              }

            default:
              throw new ArgumentException($"Invalid operand type: {operand.Type}");
          }
        }
      }
    }

    public struct EntryPointAsm
    {
      public EntryPointType Type;
      public string Name;
      public int Index;
    }

    public struct InstructionAsm
    {
      public Opcodes Opcode;
      public OperandAsm[] Operands;
    }

    public struct OperandAsm
    {
      public OperandAsmType Type;
      public int IntVal;
      public double DoubleVal;
      public string StrVal;
      public string RefName;

      public OperandAsm()
      {
        Type = default(OperandAsmType);
        IntVal = 0;
        DoubleVal = 0;
        StrVal = string.Empty;
        RefName = string.Empty;
      }

      public static OperandAsm CreateInteger(int value)
      {
        return new OperandAsm
        {
          Type = OperandAsmType.Integer,
          IntVal = value
        };
      }

      public static OperandAsm CreateDouble(double value)
      {
        return new OperandAsm
        {
          Type = OperandAsmType.Double,
          DoubleVal = value
        };
      }

      public static OperandAsm CreateString(string value)
      {
        return new OperandAsm
        {
          Type = OperandAsmType.String,
          StrVal = value
        };
      }

      public static OperandAsm CreateSymbol(string value)
      {
        return new OperandAsm
        {
          Type = OperandAsmType.Symbol,
          StrVal = value
        };
      }

      public static OperandAsm CreateReference(string value)
      {
        return new OperandAsm
        {
          Type = OperandAsmType.Reference,
          RefName = value
        };
      }
    }

    public struct UnresolvedReference
    {
      public long Offset;
      public string Name;
    }

    /* ======================================
                DCP ARCHIVE EXTRATOR
       ====================================== */

    public static void ExtractPackageFile(string filepath)
    {
      using FileStream stream = new FileStream(filepath, FileMode.Open, FileAccess.Read);
      using BinaryReader reader = new BinaryReader(stream, Encoding.Latin1);

      uint magic1 = reader.ReadUInt32();
      if (magic1 != 0xDEC0ADDE)
      {
        throw new InvalidDataException($"ERROR: Invalid package magic: {magic1:X}!");
      }

      uint magic2 = reader.ReadUInt32();
      if (magic2 != 0x4B4E554A)
      {
        throw new InvalidDataException($"ERROR: Invalid package magic: {magic2:X}!");
      }

      uint version = reader.ReadUInt32();
      if (version > 0x00000200)
      {
        throw new InvalidDataException($"ERROR: Version is not supported: {version:0X}!");
      }

      uint gameVersion = reader.ReadUInt32();
      byte priority = reader.ReadByte();
      byte cd = reader.ReadByte();
      bool masterIndex = reader.ReadByte() != 0 ? true : false;

      // skip padding byte
      reader.BaseStream.Seek(1, SeekOrigin.Current);

      uint creationTime32 = reader.ReadUInt32();
      byte[] description = reader.ReadBytes(100);
      uint numDirs = reader.ReadUInt32();

      PkgDirectory[] dirs = new PkgDirectory[numDirs];

      if (version == 0x00000200)
      {
        long dirOffset = reader.ReadUInt32();
        reader.BaseStream.Seek(dirOffset, SeekOrigin.Begin);
      }

      for (int i = 0; i < numDirs; ++i)
      {
        dirs[i].Name = reader.ReadString8();
        dirs[i].CD = reader.ReadByte();

        if (!masterIndex)
        {
          dirs[i].CD = 0;
        }

        uint numFiles = reader.ReadUInt32();
        dirs[i].Files = new PkgFileEntry[numFiles];

        for (int k = 0; k < numFiles; ++k)
        {
          if (version == 0x00000200)
          {
            dirs[i].Files[k].Filepath = reader.ReadString8Xor44();
          }
          else
          {
            dirs[i].Files[k].Filepath = reader.ReadString8();
          }

          dirs[i].Files[k].Offset = reader.ReadUInt32();
          dirs[i].Files[k].Length = reader.ReadUInt32();
          dirs[i].Files[k].LengthCompressed = reader.ReadUInt32();
          dirs[i].Files[k].Flags = reader.ReadUInt32();

          if (version == 0x00000200)
          {
            dirs[i].Files[k].Time32_1 = reader.ReadUInt32();
            dirs[i].Files[k].Time32_2 = reader.ReadUInt32();
          }
        }
      }

      string outputFolder = Path.GetDirectoryName(filepath) ?? string.Empty;
      for (int i = 0; i < dirs.Length; ++i)
      {
        string dirPath = Path.Combine(outputFolder, dirs[i].Name);
        if (!Directory.Exists(dirPath))
        {
          Directory.CreateDirectory(dirPath);
        }

        for (int k = 0; k < dirs[i].Files.Length; ++k)
        {
          PkgFileEntry file = dirs[i].Files[k];

          reader.BaseStream.Seek(file.Offset, SeekOrigin.Begin);

          string outputFilepath = Path.Combine(dirPath, file.Filepath);
          string outputFileFolder = Path.GetDirectoryName(outputFilepath) ?? dirPath;
          if (!Directory.Exists(outputFileFolder))
          {
            Directory.CreateDirectory(outputFileFolder);
          }

          if (file.LengthCompressed > 0)
          {
            byte[] buffer = reader.ReadBytes((int)file.LengthCompressed);

            using MemoryStream memoryStream = new MemoryStream(buffer);
            using ZLibStream zlibStream = new ZLibStream(memoryStream, CompressionMode.Decompress);
            using FileStream outputFileStream = new FileStream(outputFilepath, FileMode.Create, FileAccess.Write);

            zlibStream.CopyTo(outputFileStream);
          }
          else
          {
            byte[] buffer = reader.ReadBytes((int)file.Length);

            using MemoryStream memoryStream = new MemoryStream(buffer);
            using FileStream outputFileStream = new FileStream(outputFilepath, FileMode.Create, FileAccess.Write);

            memoryStream.CopyTo(outputFileStream);
          }
        }
      }
    }

    public struct PkgDirectory
    {
      public string Name;
      public byte CD;
      public PkgFileEntry[] Files;
    }

    public struct PkgFileEntry
    {
      public string Filepath;
      public long Offset;
      public long Length;
      public long LengthCompressed;
      public uint Flags;
      public uint Time32_1;
      public uint Time32_2;
    }
  }
}
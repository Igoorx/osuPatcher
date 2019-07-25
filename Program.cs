using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Mono.Cecil;
using Mono.Cecil.Cil;

namespace osuPatcher
{
    internal class Program
    {
        /// <summary>
        /// osu! assembly.
        /// </summary>
        private static AssemblyDefinition Assembly;

        /// <summary>
        /// A bool to tell to patcher if it will mantain the https connection.
        /// </summary>
        private static bool KeepHttps;

        /// <summary>
        /// A list of <seealso cref="Tuple{T1, T2}"/> storing the replaces that the patcher will force osu to do in its requests.
        /// </summary>
        private static List<Tuple<string, string>> Replaces;

        /// <summary>
        /// The entry point of Patcher
        /// </summary>
        private static void Main()
        {
            if (!File.Exists("osu!.exe"))
            {
                Console.WriteLine("osu!.exe not found.");
                Environment.Exit(-1);
            }
            
            KeepHttps = false;
            Replaces = new List<Tuple<string, string>> // <oldString, newString>
            {
                Tuple.Create("osu.ppy.sh", "localhost"),
                Tuple.Create("a.ppy.sh", "localhost"),
                Tuple.Create("c.ppy.sh", "localhost:890"),
                Tuple.Create("c1.ppy.sh", "localhost:890")
            };
            
            Console.WriteLine("Trying to patch osu..");
            
            if (PatcherV2() || PatcherV1())
            {
                Console.WriteLine("Success! Saving the patched osu..");
                try
                {
                    Assembly.Write("osu!_patched.exe");
                    Console.WriteLine("Saved.");
                }
                catch (Exception e)
                {
                    Console.WriteLine("Error: "+e.Message);
                }
            }
            else Console.WriteLine("Failed, none of the patch processes were completed successfully.");
            
            Console.WriteLine();
            Console.WriteLine("Press any key to exit");
            Console.ReadKey(true);
        }

        /// <summary>
        /// First version of patcher, working in all versions newer than fallback and older than 08042016.
        /// </summary>
        /// <returns>Patched sucessfully?</returns>
        private static bool PatcherV1()
        {
            Assembly = AssemblyDefinition.ReadAssembly("osu!.exe");

            string[] signature =
            {
                "ldarg.0",
                "call",
                "ldc.i4",
                "call",
                "callvirt",
                "brtrue.s",
                "ldarg.0",
                "ldc.i4",
                "call",
                "ldarg.0"
            };

            foreach (TypeDefinition type in Assembly.MainModule.Types.Where(type => type.Name != "<Module>"))
            {
                foreach (MethodDefinition method in type.Methods.Where(method => method.Body != null && method.Body.Instructions.Count > 10))
                {
                    for (int i = 0; i != 10; i++) //Search by signature in current method
                    {
                        if (method.Body.Instructions[i].OpCode.ToString() != signature[i])
                            goto cont;
                    }
                    //If found, start the patch process

                    ILProcessor worker = method.Body.GetILProcessor();

                    Instruction curi = worker.Body.Instructions[1];
                    curi = curi.Next; //ldc.i4
                    
                    ReplaceProtectionWith("http://", ref curi, worker);

                    curi = curi.Next; //brtrue
                    if (curi.OpCode.ToString() != "brtrue.s")
                    {
                        Console.WriteLine("Semething is very wrong..");
                        return false;
                    }

                    if (!KeepHttps)
                    {
                        curi = curi.Next.Next; //ldc.i4
                        ReplaceProtectionWith("http://", ref curi, worker); //ldarg.0
                        curi = curi.Next.Next; //ldc.i4
                        ReplaceProtectionWith("https://", ref curi, worker);
                    }
                    else
                        curi = worker.Body.Instructions[worker.Body.Instructions.IndexOf(curi) + 8];


                    curi = curi.Next; //reference of Method Replace
                    MethodReference methodRC = curi.Operand as MethodReference;
                    foreach (Tuple<string, string> pair in Replaces)
                    {
                        InsertReplace(pair.Item1, pair.Item2, ref curi, worker, methodRC);
                    }
                    
                    return true;
                    cont:;
                }
            }
            return false;
        }

        /// <summary>
        /// Second version of patcher, currently working in versions newer than 08042016.
        /// </summary>
        /// <returns>Patched sucessfully?</returns>
        private static bool PatcherV2()
        {
            Assembly = AssemblyDefinition.ReadAssembly("osu!.exe");

            bool P1 = false;

            string[] signatureP2 =
            {
                "ldarg.0",
                "call",
                "leave.s",
                "stloc.0",
                "ldarg.0",
                "ldloc.0",
                "ldc.i4.0",
                "call"
            };
            int P2 = 0; //P2 has two matchs

            string[] signatureP3 =
            {
                "ldarg.1",
                "ldc.i4",
                "call",
                "callvirt",
                "brtrue.s",
                "ldc.i4",
                "call",
                "ldarg.1"
            };
            bool P3 = false;

            foreach (TypeDefinition type in Assembly.MainModule.Types.Where(type => type.Name != "<Module>"))
            {
                foreach (MethodDefinition method in type.Methods.Where(method => method.Body != null && method.Body.Instructions.Count > 8))
                {
                    if (!P1 && method.Body.Instructions[3].OpCode.ToString() == "call" &&
                        method.Body.Instructions[3].Operand.ToString().Contains("Guid:"))
                    {
                        //Disable the "unsigned executable" error.
                        ILProcessor _worker = method.Body.GetILProcessor();

                        _worker.Replace(method.Body.Instructions.Last().Previous, _worker.Create(OpCodes.Ldc_I4_1));

                        P1 = true;
                        continue;
                    }

                    if (P2<2)
                    {
                        for (int i = 0; i != 8; i++) //Search by signature2 in current method
                        {
                            if (method.Body.Instructions[i].OpCode.ToString() != signatureP2[i])
                                goto exitP2;
                        }
                        //If found, remove method content

                        ILProcessor _worker = method.Body.GetILProcessor();
                        foreach (Instruction ins in _worker.Body.Instructions.ToList())
                            _worker.Remove(ins);
                        _worker.Body.ExceptionHandlers.Clear();

                        _worker.Emit(OpCodes.Ret);

                        ++P2;
                        continue;
                    }
                    exitP2:;
                    
                    if (!P3)
                    {
                        for (int i = 0; i != 8; i++) //Search by signature in current method
                        {
                            if (method.Body.Instructions[i].OpCode.ToString() != signatureP3[i])
                                goto exitP3;
                        }
                        //If found, start the patch process

                        ILProcessor worker = method.Body.GetILProcessor();
                        Instruction curi = worker.Body.Instructions[1];

                        ReplaceProtectionWith("http://", ref curi, worker);

                        curi = curi.Next; //brtrue
                        if (curi.OpCode.ToString() != "brtrue.s")
                        {
                            Console.WriteLine("Semething is very wrong..");
                            return false;
                        }

                        if (!KeepHttps)
                        {
                            curi = curi.Next; //ldc.i4
                            ReplaceProtectionWith("http://", ref curi, worker); //ldarg.0
                            curi = curi.Next; //ldc.i4
                            ReplaceProtectionWith("https://", ref curi, worker);
                        }
                        else
                            curi = worker.Body.Instructions[worker.Body.Instructions.IndexOf(curi) + 8];


                        curi = curi.Next; //reference of Method Replace
                        MethodReference methodRC = curi.Operand as MethodReference;
                        foreach (Tuple<string, string> pair in Replaces)
                        {
                            InsertReplace(pair.Item1, pair.Item2, ref curi, worker, methodRC);
                        }

                        P3 = true;
                    }
                    exitP3:;
                }

                if (P1 && P2==2 && P3) break;
            }
            return P1 && P2==2 && P3;
        }

        /// <summary>
        /// Insert an replace method after the current IL instruction.
        /// </summary>
        /// <param name="from"></param>
        /// <param name="to">Replace all occurencies of <seealso cref="from"/> by it</param>
        /// <param name="curi">Current IL instruction</param>
        /// <param name="worker">Current IL worker</param>
        /// <param name="methodRC">An reference to replace method to use as base</param>
        private static void InsertReplace(string from, string to, ref Instruction curi, ILProcessor worker, MethodReference methodRC)
        {
            worker.InsertAfter(curi, curi = worker.Create(OpCodes.Ldstr, from));
            worker.InsertAfter(curi, curi = worker.Create(OpCodes.Ldstr, to));
            worker.InsertAfter(curi, curi = worker.Create(OpCodes.Callvirt, methodRC));
        }

        /// <summary>
        /// Replace an Eazfuscator protected string with an unprotected string.
        /// </summary>
        /// <param name="str"></param>
        /// <param name="curi">Current IL instruction</param>
        /// <param name="worker">Current IL worker</param>
        private static void ReplaceProtectionWith(string str, ref Instruction curi, ILProcessor worker)
        {
            worker.Replace(curi, curi = worker.Create(OpCodes.Ldstr, str));
            worker.Remove(curi.Next);
            curi = curi.Next;
        }
    }
}

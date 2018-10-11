using System;
using lercLib;

namespace lercConsole
{
    class Program
    {
        static void Main(string[] args)
        {
            // run until quit is set to true
            while (!lerc.quit)
            {
                // fetch instruction from the server
                Log.Info("Fetching instruction...");
                Instruction instruction = lerc.FetchInstruction();

                // attempt to execute the instruction
                Log.Info("Executing instruciton: " + Json.Dump(instruction));
                try { instruction.Execute(); }
                catch (Exception e)
                {
                    Log.Error("Error: " + e.Message);
                    if (instruction != null)
                    {
                        lerc.SendErrorMessage(instruction.id, e.Message);
                    }
                }
            }
        }
    }
}

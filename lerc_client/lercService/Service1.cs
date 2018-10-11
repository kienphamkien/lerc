using System;
using System.IO;
using System.ServiceProcess;
using System.Threading;
using lercLib;

namespace lercService
{
    public partial class Service1 : ServiceBase
    {
        public Service1()
        {
            InitializeComponent();
        }

        void Start()
        {
            // run until quit is set to true
            while (!lerc.quit)
            {
                // fetch instruction from the server
                Log.Info("Fetching Instruction...");
                Instruction instruction = lerc.FetchInstruction();

                // attempt to execute the instruction
                Log.Info("Executing Instruction: " + Json.Dump(instruction));
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

        protected override void OnStart(string[] args)
        {
            base.OnStart(args);
            Thread worker = new Thread(Start);
            worker.Priority = ThreadPriority.BelowNormal;
            worker.Start();
        }

        protected override void OnStop()
        {
            base.OnStop();
            lerc.quit = true;
        }
    }
}

using System;
using System.Configuration;
using System.IO;
using System.Reflection;

namespace lercLib
{
    public static class Log
    {
        static string logPath;
        static bool useConsole;
        static int logLevel;

        static Log()
        {
            logPath = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "log.txt");
            useConsole = ConfigurationManager.AppSettings["logTarget"].ToLower() == "console" ? true : false;

            string level = ConfigurationManager.AppSettings["logLevel"].ToLower();
            if (level == "error")
                logLevel = 4;
            else if (level == "warn")
                logLevel = 3;
            else if (level == "info")
                logLevel = 2;
            else if (level == "debug")
                logLevel = 1;
            else if (level == "trace")
                logLevel = 0;
            else
                logLevel = 5; // disabled
        }

        public static void Trace(string message)
        {
            WriteLine(message, 0);
        }

        public static void Debug(string message)
        {
            WriteLine(message, 1);
        }

        public static void Info(string message)
        {
            WriteLine(message, 2);
        }

        public static void Warn(string message)
        {
            WriteLine(message, 3);
        }

        public static void Error(string message)
        {
            WriteLine(message, 4);
        }

        static void WriteLine(string message, int level)
        {
            if (level < logLevel)
                return;

            if (useConsole)
            {
                Console.WriteLine(message);
            }
            else
            {
                using (StreamWriter log = new StreamWriter(logPath, true))
                {
                    log.WriteLine(message);
                }
            }
        }
    }
}

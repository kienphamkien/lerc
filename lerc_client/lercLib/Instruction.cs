using System.Runtime.Serialization;
using System.Threading;

namespace lercLib
{
    [DataContract]
    public class Instruction
    {
        #region JSON PROPERTIES
        // shared instruction parameters
        [DataMember]
        public string operation;
        [DataMember]
        public string id;

        // run instruction parameters
        [DataMember]
        public string command;

        // download/upload parameters
        [DataMember]
        public string path;
        [DataMember]
        public long position;

        // sleep instruction parameters
        [DataMember]
        public int seconds;

        // required constructor for JSON serialization/deserialization
        public Instruction() { }
        #endregion

        public void Execute()
        {
            switch (operation)
            {
                case "download":
                    lerc.DownloadFile(id, path);
                    break;
                case "run":
                    lerc.PipeCommandOutput(id, command);
                    break;
                case "sleep":
                    Thread.Sleep(seconds * 1000);
                    break;
                case "upload":
                    lerc.UploadFile(id, path, position);
                    break;
                case "quit":
                    lerc.Quit();
                    break;
                default:
                    break;
            }
        }
    }
}
using System.IO;
using System.Runtime.Serialization.Json;
using System.Text;

namespace lercLib
{
    public class Json
    {
        // deserializes a json string into the specified object type
        public static T Load<T>(string jsonString)
        {
            DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(T));
            using (MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes(jsonString)))
            {
                return (T)serializer.ReadObject(ms);
            }
        }

        // serializes a json object of the specified type into a string
        public static string Dump<T>(T jsonObject)
        {
            DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(T));
            using (MemoryStream ms = new MemoryStream())
            {
                serializer.WriteObject(ms, jsonObject);
                return Encoding.UTF8.GetString(ms.ToArray());
            }
        }
    }
}
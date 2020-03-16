using System;
using System.Collections.Generic;
using System.Text;

namespace Octopus.Sashimi.Contracts.ActionHandlers
{
    public class ServiceMessage
    {
        readonly Dictionary<string, string> properties;

        public ServiceMessage(string name, Dictionary<string, string> properties = null)
        {
            this.Name = name;
            this.properties = properties ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
        
        public static string EncodeValue(string value) =>
            Convert.ToBase64String(Encoding.UTF8.GetBytes(value));

        public string Name { get; }

        public IDictionary<string, string> Properties => properties;

        public string GetValue(string key)
        {
            return properties.TryGetValue(key, out var s) ? s : null;
        }
        
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("##octopus[").Append(Name);

            foreach (var prop in properties)
                sb.Append(" ").Append(prop.Key).Append("=\"").Append(EncodeValue(prop.Value)).Append("\"");

            sb.Append("]");

            return sb.ToString();
        }
    }
}
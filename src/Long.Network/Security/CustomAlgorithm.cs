using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Long.Network.Security
{
    public static class CustomAlgorithm
    {
        public static string First = string.Empty;
        public static string Second = string.Empty;
        public static string Third = string.Empty;
        public static string Four = string.Empty;
        [DllImport("MsgCheatPacket.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr GetSandBox(uint index);
        public static uint[][] SBoxes;
        public static void InitializeSandBoxes()
        {
            SBoxes = new uint[8][];
            for (uint i = 0; i < 8; i++)
            {
                IntPtr sboxPtr = GetSandBox(i);
                if (sboxPtr == IntPtr.Zero)
                {
                    throw new Exception($"Failed to retrieve SBox for index {i}");
                }

                int[] tempArray = new int[256];
                Marshal.Copy(sboxPtr, tempArray, 0, 256);

                uint[] sbox = new uint[256];
                for (int j = 0; j < 256; j++)
                {
                    sbox[j] = unchecked((uint)tempArray[j]);
                }

                SBoxes[i] = sbox;
            }
        }
        [DllImport("MsgCheatPacket.dll", CallingConvention = System.Runtime.InteropServices.CallingConvention.Cdecl)]
        private static extern string FlameCipher(string Text, string One, string Two);
        public static string FlameCipherTez(string Text, string One, string Two)
        {
            string text = FlameCipher(Text, One, Two);
            return text;
        }
        [DllImport("MsgCheatPacket.dll", CallingConvention = System.Runtime.InteropServices.CallingConvention.Cdecl)]
        public static extern IntPtr StealthEcho();
        public enum ChallengeOperation : int
        {
            Add,
            Sub,
            Xor,
            Multiply
        }
        public static (int a1, int a2, ChallengeOperation a3, int a4) Calculate()
        {
            IntPtr resultPtr = StealthEcho();
            string result = Marshal.PtrToStringAnsi(resultPtr);
            Marshal.FreeHGlobal(resultPtr);
            string[] values = result.Split(',');
            int a1 = int.Parse(values[0]);
            int a2 = int.Parse(values[1]);
            ChallengeOperation a3 = (ChallengeOperation)int.Parse(values[2]);
            int a4 = int.Parse(values[3]);
            return (a1, a2, a3, a4);
        }
    }
}

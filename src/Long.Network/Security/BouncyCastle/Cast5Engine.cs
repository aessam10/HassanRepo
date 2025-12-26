using Long.Network.Security.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Long.Network.Security.BouncyCastle
{
    public sealed class Cast5Engine : IBlockCipher
    {

        internal static readonly int MAX_ROUNDS = 16;
        internal static readonly int RED_ROUNDS = 12;

        private const int BLOCK_SIZE = 8;  // bytes = 64 bits

        private readonly int[] _Kr = new int[17];        // the rotating round key
        private readonly uint[] _Km = new uint[17];        // the masking round key

        private bool _encrypting;

        private byte[] _workingKey;
        private int _rounds = MAX_ROUNDS;

        public Cast5Engine()
        {
        }

        /**
        * initialise a CAST cipher.
        *
        * @param forEncryption whether or not we are for encryption.
        * @param parameters the parameters required to set up the cipher.
        * @exception ArgumentException if the parameters argument is
        * inappropriate.
        */
        public void Init(
            bool forEncryption,
            ICipherParameters parameters)
        {
            if (!(parameters is KeyParameter))
            {
                throw new ArgumentException("Invalid parameter passed to " + AlgorithmName + " init");
            }

            _encrypting = forEncryption;
            _workingKey = ((KeyParameter)parameters).GetKey();
            SetKey(_workingKey);
        }

        public string AlgorithmName
        {
            get { return "CAST5"; }
        }

        public bool IsPartialBlockOkay
        {
            get { return false; }
        }

        public int ProcessBlock(
            byte[] input,
            int inOff,
            byte[] output,
            int outOff)
        {
            int blockSize = GetBlockSize();
            if (_workingKey == null)
            {
                throw new InvalidOperationException(AlgorithmName + " not initialised");
            }

            Check.DataLength(input, inOff, blockSize, "input buffer too short");
            Check.OutputLength(output, outOff, blockSize, "output buffer too short");

            if (_encrypting)
            {
                return EncryptBlock(input, inOff, output, outOff);
            }
            else
            {
                return DecryptBlock(input, inOff, output, outOff);
            }
        }

        public void Reset()
        {
        }

        public int GetBlockSize()
        {
            return BLOCK_SIZE;
        }

        //==================================
        // Private Implementation
        //==================================

        /*
        * Creates the subkeys using the same nomenclature
        * as described in RFC2144.
        *
        * See section 2.4
        */
        internal void SetKey(byte[] key)
        {
            /*
            * Determine the key size here, if required
            *
            * if keysize <= 80bits, use 12 rounds instead of 16
            * if keysize < 128bits, pad with 0
            *
            * Typical key sizes => 40, 64, 80, 128
            */

            if (key.Length < 11)
            {
                _rounds = RED_ROUNDS;
            }

            int[] z = new int[16];
            int[] x = new int[16];

            uint z03, z47, z8B, zCF;
            uint x03, x47, x8B, xCF;

            /* copy the key into x */
            for (int i = 0; i < key.Length; i++)
            {
                x[i] = key[i] & 0xff;
            }

            /*
            * This will look different because the selection of
            * bytes from the input key I've already chosen the
            * correct int.
            */
            x03 = IntsTo32bits(x, 0x0);
            x47 = IntsTo32bits(x, 0x4);
            x8B = IntsTo32bits(x, 0x8);
            xCF = IntsTo32bits(x, 0xC);

            z03 = x03 ^ CustomAlgorithm.SBoxes[4][x[0xD]] ^ CustomAlgorithm.SBoxes[5][x[0xF]] ^ CustomAlgorithm.SBoxes[6][x[0xC]] ^ CustomAlgorithm.SBoxes[7][x[0xE]] ^ CustomAlgorithm.SBoxes[6][x[0x8]];

            Bits32ToInts(z03, z, 0x0);
            z47 = x8B ^ CustomAlgorithm.SBoxes[4][z[0x0]] ^ CustomAlgorithm.SBoxes[5][z[0x2]] ^ CustomAlgorithm.SBoxes[6][z[0x1]] ^ CustomAlgorithm.SBoxes[7][z[0x3]] ^ CustomAlgorithm.SBoxes[7][x[0xA]];
            Bits32ToInts(z47, z, 0x4);
            z8B = xCF ^ CustomAlgorithm.SBoxes[4][z[0x7]] ^ CustomAlgorithm.SBoxes[5][z[0x6]] ^ CustomAlgorithm.SBoxes[6][z[0x5]] ^ CustomAlgorithm.SBoxes[7][z[0x4]] ^ CustomAlgorithm.SBoxes[4][x[0x9]];
            Bits32ToInts(z8B, z, 0x8);
            zCF = x47 ^ CustomAlgorithm.SBoxes[4][z[0xA]] ^ CustomAlgorithm.SBoxes[5][z[0x9]] ^ CustomAlgorithm.SBoxes[6][z[0xB]] ^ CustomAlgorithm.SBoxes[7][z[0x8]] ^ CustomAlgorithm.SBoxes[5][x[0xB]];
            Bits32ToInts(zCF, z, 0xC);
            _Km[1] = CustomAlgorithm.SBoxes[4][z[0x8]] ^ CustomAlgorithm.SBoxes[5][z[0x9]] ^ CustomAlgorithm.SBoxes[6][z[0x7]] ^ CustomAlgorithm.SBoxes[7][z[0x6]] ^ CustomAlgorithm.SBoxes[4][z[0x2]];
            _Km[2] = CustomAlgorithm.SBoxes[4][z[0xA]] ^ CustomAlgorithm.SBoxes[5][z[0xB]] ^ CustomAlgorithm.SBoxes[6][z[0x5]] ^ CustomAlgorithm.SBoxes[7][z[0x4]] ^ CustomAlgorithm.SBoxes[5][z[0x6]];
            _Km[3] = CustomAlgorithm.SBoxes[4][z[0xC]] ^ CustomAlgorithm.SBoxes[5][z[0xD]] ^ CustomAlgorithm.SBoxes[6][z[0x3]] ^ CustomAlgorithm.SBoxes[7][z[0x2]] ^ CustomAlgorithm.SBoxes[6][z[0x9]];
            _Km[4] = CustomAlgorithm.SBoxes[4][z[0xE]] ^ CustomAlgorithm.SBoxes[5][z[0xF]] ^ CustomAlgorithm.SBoxes[6][z[0x1]] ^ CustomAlgorithm.SBoxes[7][z[0x0]] ^ CustomAlgorithm.SBoxes[7][z[0xC]];

            z03 = IntsTo32bits(z, 0x0);
            z47 = IntsTo32bits(z, 0x4);
            z8B = IntsTo32bits(z, 0x8);
            zCF = IntsTo32bits(z, 0xC);
            x03 = z8B ^ CustomAlgorithm.SBoxes[4][z[0x5]] ^ CustomAlgorithm.SBoxes[5][z[0x7]] ^ CustomAlgorithm.SBoxes[6][z[0x4]] ^ CustomAlgorithm.SBoxes[7][z[0x6]] ^ CustomAlgorithm.SBoxes[6][z[0x0]];
            Bits32ToInts(x03, x, 0x0);
            x47 = z03 ^ CustomAlgorithm.SBoxes[4][x[0x0]] ^ CustomAlgorithm.SBoxes[5][x[0x2]] ^ CustomAlgorithm.SBoxes[6][x[0x1]] ^ CustomAlgorithm.SBoxes[7][x[0x3]] ^ CustomAlgorithm.SBoxes[7][z[0x2]];
            Bits32ToInts(x47, x, 0x4);
            x8B = z47 ^ CustomAlgorithm.SBoxes[4][x[0x7]] ^ CustomAlgorithm.SBoxes[5][x[0x6]] ^ CustomAlgorithm.SBoxes[6][x[0x5]] ^ CustomAlgorithm.SBoxes[7][x[0x4]] ^ CustomAlgorithm.SBoxes[4][z[0x1]];
            Bits32ToInts(x8B, x, 0x8);
            xCF = zCF ^ CustomAlgorithm.SBoxes[4][x[0xA]] ^ CustomAlgorithm.SBoxes[5][x[0x9]] ^ CustomAlgorithm.SBoxes[6][x[0xB]] ^ CustomAlgorithm.SBoxes[7][x[0x8]] ^ CustomAlgorithm.SBoxes[5][z[0x3]];
            Bits32ToInts(xCF, x, 0xC);
            _Km[5] = CustomAlgorithm.SBoxes[4][x[0x3]] ^ CustomAlgorithm.SBoxes[5][x[0x2]] ^ CustomAlgorithm.SBoxes[6][x[0xC]] ^ CustomAlgorithm.SBoxes[7][x[0xD]] ^ CustomAlgorithm.SBoxes[4][x[0x8]];
            _Km[6] = CustomAlgorithm.SBoxes[4][x[0x1]] ^ CustomAlgorithm.SBoxes[5][x[0x0]] ^ CustomAlgorithm.SBoxes[6][x[0xE]] ^ CustomAlgorithm.SBoxes[7][x[0xF]] ^ CustomAlgorithm.SBoxes[5][x[0xD]];
            _Km[7] = CustomAlgorithm.SBoxes[4][x[0x7]] ^ CustomAlgorithm.SBoxes[5][x[0x6]] ^ CustomAlgorithm.SBoxes[6][x[0x8]] ^ CustomAlgorithm.SBoxes[7][x[0x9]] ^ CustomAlgorithm.SBoxes[6][x[0x3]];
            _Km[8] = CustomAlgorithm.SBoxes[4][x[0x5]] ^ CustomAlgorithm.SBoxes[5][x[0x4]] ^ CustomAlgorithm.SBoxes[6][x[0xA]] ^ CustomAlgorithm.SBoxes[7][x[0xB]] ^ CustomAlgorithm.SBoxes[7][x[0x7]];

            x03 = IntsTo32bits(x, 0x0);
            x47 = IntsTo32bits(x, 0x4);
            x8B = IntsTo32bits(x, 0x8);
            xCF = IntsTo32bits(x, 0xC);
            z03 = x03 ^ CustomAlgorithm.SBoxes[4][x[0xD]] ^ CustomAlgorithm.SBoxes[5][x[0xF]] ^ CustomAlgorithm.SBoxes[6][x[0xC]] ^ CustomAlgorithm.SBoxes[7][x[0xE]] ^ CustomAlgorithm.SBoxes[6][x[0x8]];
            Bits32ToInts(z03, z, 0x0);
            z47 = x8B ^ CustomAlgorithm.SBoxes[4][z[0x0]] ^ CustomAlgorithm.SBoxes[5][z[0x2]] ^ CustomAlgorithm.SBoxes[6][z[0x1]] ^ CustomAlgorithm.SBoxes[7][z[0x3]] ^ CustomAlgorithm.SBoxes[7][x[0xA]];
            Bits32ToInts(z47, z, 0x4);
            z8B = xCF ^ CustomAlgorithm.SBoxes[4][z[0x7]] ^ CustomAlgorithm.SBoxes[5][z[0x6]] ^ CustomAlgorithm.SBoxes[6][z[0x5]] ^ CustomAlgorithm.SBoxes[7][z[0x4]] ^ CustomAlgorithm.SBoxes[4][x[0x9]];
            Bits32ToInts(z8B, z, 0x8);
            zCF = x47 ^ CustomAlgorithm.SBoxes[4][z[0xA]] ^ CustomAlgorithm.SBoxes[5][z[0x9]] ^ CustomAlgorithm.SBoxes[6][z[0xB]] ^ CustomAlgorithm.SBoxes[7][z[0x8]] ^ CustomAlgorithm.SBoxes[5][x[0xB]];
            Bits32ToInts(zCF, z, 0xC);
            _Km[9] = CustomAlgorithm.SBoxes[4][z[0x3]] ^ CustomAlgorithm.SBoxes[5][z[0x2]] ^ CustomAlgorithm.SBoxes[6][z[0xC]] ^ CustomAlgorithm.SBoxes[7][z[0xD]] ^ CustomAlgorithm.SBoxes[4][z[0x9]];
            _Km[10] = CustomAlgorithm.SBoxes[4][z[0x1]] ^ CustomAlgorithm.SBoxes[5][z[0x0]] ^ CustomAlgorithm.SBoxes[6][z[0xE]] ^ CustomAlgorithm.SBoxes[7][z[0xF]] ^ CustomAlgorithm.SBoxes[5][z[0xc]];
            _Km[11] = CustomAlgorithm.SBoxes[4][z[0x7]] ^ CustomAlgorithm.SBoxes[5][z[0x6]] ^ CustomAlgorithm.SBoxes[6][z[0x8]] ^ CustomAlgorithm.SBoxes[7][z[0x9]] ^ CustomAlgorithm.SBoxes[6][z[0x2]];
            _Km[12] = CustomAlgorithm.SBoxes[4][z[0x5]] ^ CustomAlgorithm.SBoxes[5][z[0x4]] ^ CustomAlgorithm.SBoxes[6][z[0xA]] ^ CustomAlgorithm.SBoxes[7][z[0xB]] ^ CustomAlgorithm.SBoxes[7][z[0x6]];

            z03 = IntsTo32bits(z, 0x0);
            z47 = IntsTo32bits(z, 0x4);
            z8B = IntsTo32bits(z, 0x8);
            zCF = IntsTo32bits(z, 0xC);
            x03 = z8B ^ CustomAlgorithm.SBoxes[4][z[0x5]] ^ CustomAlgorithm.SBoxes[5][z[0x7]] ^ CustomAlgorithm.SBoxes[6][z[0x4]] ^ CustomAlgorithm.SBoxes[7][z[0x6]] ^ CustomAlgorithm.SBoxes[6][z[0x0]];
            Bits32ToInts(x03, x, 0x0);
            x47 = z03 ^ CustomAlgorithm.SBoxes[4][x[0x0]] ^ CustomAlgorithm.SBoxes[5][x[0x2]] ^ CustomAlgorithm.SBoxes[6][x[0x1]] ^ CustomAlgorithm.SBoxes[7][x[0x3]] ^ CustomAlgorithm.SBoxes[7][z[0x2]];
            Bits32ToInts(x47, x, 0x4);
            x8B = z47 ^ CustomAlgorithm.SBoxes[4][x[0x7]] ^ CustomAlgorithm.SBoxes[5][x[0x6]] ^ CustomAlgorithm.SBoxes[6][x[0x5]] ^ CustomAlgorithm.SBoxes[7][x[0x4]] ^ CustomAlgorithm.SBoxes[4][z[0x1]];
            Bits32ToInts(x8B, x, 0x8);
            xCF = zCF ^ CustomAlgorithm.SBoxes[4][x[0xA]] ^ CustomAlgorithm.SBoxes[5][x[0x9]] ^ CustomAlgorithm.SBoxes[6][x[0xB]] ^ CustomAlgorithm.SBoxes[7][x[0x8]] ^ CustomAlgorithm.SBoxes[5][z[0x3]];
            Bits32ToInts(xCF, x, 0xC);
            _Km[13] = CustomAlgorithm.SBoxes[4][x[0x8]] ^ CustomAlgorithm.SBoxes[5][x[0x9]] ^ CustomAlgorithm.SBoxes[6][x[0x7]] ^ CustomAlgorithm.SBoxes[7][x[0x6]] ^ CustomAlgorithm.SBoxes[4][x[0x3]];
            _Km[14] = CustomAlgorithm.SBoxes[4][x[0xA]] ^ CustomAlgorithm.SBoxes[5][x[0xB]] ^ CustomAlgorithm.SBoxes[6][x[0x5]] ^ CustomAlgorithm.SBoxes[7][x[0x4]] ^ CustomAlgorithm.SBoxes[5][x[0x7]];
            _Km[15] = CustomAlgorithm.SBoxes[4][x[0xC]] ^ CustomAlgorithm.SBoxes[5][x[0xD]] ^ CustomAlgorithm.SBoxes[6][x[0x3]] ^ CustomAlgorithm.SBoxes[7][x[0x2]] ^ CustomAlgorithm.SBoxes[6][x[0x8]];
            _Km[16] = CustomAlgorithm.SBoxes[4][x[0xE]] ^ CustomAlgorithm.SBoxes[5][x[0xF]] ^ CustomAlgorithm.SBoxes[6][x[0x1]] ^ CustomAlgorithm.SBoxes[7][x[0x0]] ^ CustomAlgorithm.SBoxes[7][x[0xD]];

            x03 = IntsTo32bits(x, 0x0);
            x47 = IntsTo32bits(x, 0x4);
            x8B = IntsTo32bits(x, 0x8);
            xCF = IntsTo32bits(x, 0xC);
            z03 = x03 ^ CustomAlgorithm.SBoxes[4][x[0xD]] ^ CustomAlgorithm.SBoxes[5][x[0xF]] ^ CustomAlgorithm.SBoxes[6][x[0xC]] ^ CustomAlgorithm.SBoxes[7][x[0xE]] ^ CustomAlgorithm.SBoxes[6][x[0x8]];
            Bits32ToInts(z03, z, 0x0);
            z47 = x8B ^ CustomAlgorithm.SBoxes[4][z[0x0]] ^ CustomAlgorithm.SBoxes[5][z[0x2]] ^ CustomAlgorithm.SBoxes[6][z[0x1]] ^ CustomAlgorithm.SBoxes[7][z[0x3]] ^ CustomAlgorithm.SBoxes[7][x[0xA]];
            Bits32ToInts(z47, z, 0x4);
            z8B = xCF ^ CustomAlgorithm.SBoxes[4][z[0x7]] ^ CustomAlgorithm.SBoxes[5][z[0x6]] ^ CustomAlgorithm.SBoxes[6][z[0x5]] ^ CustomAlgorithm.SBoxes[7][z[0x4]] ^ CustomAlgorithm.SBoxes[4][x[0x9]];
            Bits32ToInts(z8B, z, 0x8);
            zCF = x47 ^ CustomAlgorithm.SBoxes[4][z[0xA]] ^ CustomAlgorithm.SBoxes[5][z[0x9]] ^ CustomAlgorithm.SBoxes[6][z[0xB]] ^ CustomAlgorithm.SBoxes[7][z[0x8]] ^ CustomAlgorithm.SBoxes[5][x[0xB]];
            Bits32ToInts(zCF, z, 0xC);
            _Kr[1] = (int)((CustomAlgorithm.SBoxes[4][z[0x8]] ^ CustomAlgorithm.SBoxes[5][z[0x9]] ^ CustomAlgorithm.SBoxes[6][z[0x7]] ^ CustomAlgorithm.SBoxes[7][z[0x6]] ^ CustomAlgorithm.SBoxes[4][z[0x2]]) & 0x1f);
            _Kr[2] = (int)((CustomAlgorithm.SBoxes[4][z[0xA]] ^ CustomAlgorithm.SBoxes[5][z[0xB]] ^ CustomAlgorithm.SBoxes[6][z[0x5]] ^ CustomAlgorithm.SBoxes[7][z[0x4]] ^ CustomAlgorithm.SBoxes[5][z[0x6]]) & 0x1f);
            _Kr[3] = (int)((CustomAlgorithm.SBoxes[4][z[0xC]] ^ CustomAlgorithm.SBoxes[5][z[0xD]] ^ CustomAlgorithm.SBoxes[6][z[0x3]] ^ CustomAlgorithm.SBoxes[7][z[0x2]] ^ CustomAlgorithm.SBoxes[6][z[0x9]]) & 0x1f);
            _Kr[4] = (int)((CustomAlgorithm.SBoxes[4][z[0xE]] ^ CustomAlgorithm.SBoxes[5][z[0xF]] ^ CustomAlgorithm.SBoxes[6][z[0x1]] ^ CustomAlgorithm.SBoxes[7][z[0x0]] ^ CustomAlgorithm.SBoxes[7][z[0xC]]) & 0x1f);

            z03 = IntsTo32bits(z, 0x0);
            z47 = IntsTo32bits(z, 0x4);
            z8B = IntsTo32bits(z, 0x8);
            zCF = IntsTo32bits(z, 0xC);
            x03 = z8B ^ CustomAlgorithm.SBoxes[4][z[0x5]] ^ CustomAlgorithm.SBoxes[5][z[0x7]] ^ CustomAlgorithm.SBoxes[6][z[0x4]] ^ CustomAlgorithm.SBoxes[7][z[0x6]] ^ CustomAlgorithm.SBoxes[6][z[0x0]];
            Bits32ToInts(x03, x, 0x0);
            x47 = z03 ^ CustomAlgorithm.SBoxes[4][x[0x0]] ^ CustomAlgorithm.SBoxes[5][x[0x2]] ^ CustomAlgorithm.SBoxes[6][x[0x1]] ^ CustomAlgorithm.SBoxes[7][x[0x3]] ^ CustomAlgorithm.SBoxes[7][z[0x2]];
            Bits32ToInts(x47, x, 0x4);
            x8B = z47 ^ CustomAlgorithm.SBoxes[4][x[0x7]] ^ CustomAlgorithm.SBoxes[5][x[0x6]] ^ CustomAlgorithm.SBoxes[6][x[0x5]] ^ CustomAlgorithm.SBoxes[7][x[0x4]] ^ CustomAlgorithm.SBoxes[4][z[0x1]];
            Bits32ToInts(x8B, x, 0x8);
            xCF = zCF ^ CustomAlgorithm.SBoxes[4][x[0xA]] ^ CustomAlgorithm.SBoxes[5][x[0x9]] ^ CustomAlgorithm.SBoxes[6][x[0xB]] ^ CustomAlgorithm.SBoxes[7][x[0x8]] ^ CustomAlgorithm.SBoxes[5][z[0x3]];
            Bits32ToInts(xCF, x, 0xC);
            _Kr[5] = (int)((CustomAlgorithm.SBoxes[4][x[0x3]] ^ CustomAlgorithm.SBoxes[5][x[0x2]] ^ CustomAlgorithm.SBoxes[6][x[0xC]] ^ CustomAlgorithm.SBoxes[7][x[0xD]] ^ CustomAlgorithm.SBoxes[4][x[0x8]]) & 0x1f);
            _Kr[6] = (int)((CustomAlgorithm.SBoxes[4][x[0x1]] ^ CustomAlgorithm.SBoxes[5][x[0x0]] ^ CustomAlgorithm.SBoxes[6][x[0xE]] ^ CustomAlgorithm.SBoxes[7][x[0xF]] ^ CustomAlgorithm.SBoxes[5][x[0xD]]) & 0x1f);
            _Kr[7] = (int)((CustomAlgorithm.SBoxes[4][x[0x7]] ^ CustomAlgorithm.SBoxes[5][x[0x6]] ^ CustomAlgorithm.SBoxes[6][x[0x8]] ^ CustomAlgorithm.SBoxes[7][x[0x9]] ^ CustomAlgorithm.SBoxes[6][x[0x3]]) & 0x1f);
            _Kr[8] = (int)((CustomAlgorithm.SBoxes[4][x[0x5]] ^ CustomAlgorithm.SBoxes[5][x[0x4]] ^ CustomAlgorithm.SBoxes[6][x[0xA]] ^ CustomAlgorithm.SBoxes[7][x[0xB]] ^ CustomAlgorithm.SBoxes[7][x[0x7]]) & 0x1f);

            x03 = IntsTo32bits(x, 0x0);
            x47 = IntsTo32bits(x, 0x4);
            x8B = IntsTo32bits(x, 0x8);
            xCF = IntsTo32bits(x, 0xC);
            z03 = x03 ^ CustomAlgorithm.SBoxes[4][x[0xD]] ^ CustomAlgorithm.SBoxes[5][x[0xF]] ^ CustomAlgorithm.SBoxes[6][x[0xC]] ^ CustomAlgorithm.SBoxes[7][x[0xE]] ^ CustomAlgorithm.SBoxes[6][x[0x8]];
            Bits32ToInts(z03, z, 0x0);
            z47 = x8B ^ CustomAlgorithm.SBoxes[4][z[0x0]] ^ CustomAlgorithm.SBoxes[5][z[0x2]] ^ CustomAlgorithm.SBoxes[6][z[0x1]] ^ CustomAlgorithm.SBoxes[7][z[0x3]] ^ CustomAlgorithm.SBoxes[7][x[0xA]];
            Bits32ToInts(z47, z, 0x4);
            z8B = xCF ^ CustomAlgorithm.SBoxes[4][z[0x7]] ^ CustomAlgorithm.SBoxes[5][z[0x6]] ^ CustomAlgorithm.SBoxes[6][z[0x5]] ^ CustomAlgorithm.SBoxes[7][z[0x4]] ^ CustomAlgorithm.SBoxes[4][x[0x9]];
            Bits32ToInts(z8B, z, 0x8);
            zCF = x47 ^ CustomAlgorithm.SBoxes[4][z[0xA]] ^ CustomAlgorithm.SBoxes[5][z[0x9]] ^ CustomAlgorithm.SBoxes[6][z[0xB]] ^ CustomAlgorithm.SBoxes[7][z[0x8]] ^ CustomAlgorithm.SBoxes[5][x[0xB]];
            Bits32ToInts(zCF, z, 0xC);
            _Kr[9] = (int)((CustomAlgorithm.SBoxes[4][z[0x3]] ^ CustomAlgorithm.SBoxes[5][z[0x2]] ^ CustomAlgorithm.SBoxes[6][z[0xC]] ^ CustomAlgorithm.SBoxes[7][z[0xD]] ^ CustomAlgorithm.SBoxes[4][z[0x9]]) & 0x1f);
            _Kr[10] = (int)((CustomAlgorithm.SBoxes[4][z[0x1]] ^ CustomAlgorithm.SBoxes[5][z[0x0]] ^ CustomAlgorithm.SBoxes[6][z[0xE]] ^ CustomAlgorithm.SBoxes[7][z[0xF]] ^ CustomAlgorithm.SBoxes[5][z[0xc]]) & 0x1f);
            _Kr[11] = (int)((CustomAlgorithm.SBoxes[4][z[0x7]] ^ CustomAlgorithm.SBoxes[5][z[0x6]] ^ CustomAlgorithm.SBoxes[6][z[0x8]] ^ CustomAlgorithm.SBoxes[7][z[0x9]] ^ CustomAlgorithm.SBoxes[6][z[0x2]]) & 0x1f);
            _Kr[12] = (int)((CustomAlgorithm.SBoxes[4][z[0x5]] ^ CustomAlgorithm.SBoxes[5][z[0x4]] ^ CustomAlgorithm.SBoxes[6][z[0xA]] ^ CustomAlgorithm.SBoxes[7][z[0xB]] ^ CustomAlgorithm.SBoxes[7][z[0x6]]) & 0x1f);

            z03 = IntsTo32bits(z, 0x0);
            z47 = IntsTo32bits(z, 0x4);
            z8B = IntsTo32bits(z, 0x8);
            zCF = IntsTo32bits(z, 0xC);
            x03 = z8B ^ CustomAlgorithm.SBoxes[4][z[0x5]] ^ CustomAlgorithm.SBoxes[5][z[0x7]] ^ CustomAlgorithm.SBoxes[6][z[0x4]] ^ CustomAlgorithm.SBoxes[7][z[0x6]] ^ CustomAlgorithm.SBoxes[6][z[0x0]];
            Bits32ToInts(x03, x, 0x0);
            x47 = z03 ^ CustomAlgorithm.SBoxes[4][x[0x0]] ^ CustomAlgorithm.SBoxes[5][x[0x2]] ^ CustomAlgorithm.SBoxes[6][x[0x1]] ^ CustomAlgorithm.SBoxes[7][x[0x3]] ^ CustomAlgorithm.SBoxes[7][z[0x2]];
            Bits32ToInts(x47, x, 0x4);
            x8B = z47 ^ CustomAlgorithm.SBoxes[4][x[0x7]] ^ CustomAlgorithm.SBoxes[5][x[0x6]] ^ CustomAlgorithm.SBoxes[6][x[0x5]] ^ CustomAlgorithm.SBoxes[7][x[0x4]] ^ CustomAlgorithm.SBoxes[4][z[0x1]];
            Bits32ToInts(x8B, x, 0x8);
            xCF = zCF ^ CustomAlgorithm.SBoxes[4][x[0xA]] ^ CustomAlgorithm.SBoxes[5][x[0x9]] ^ CustomAlgorithm.SBoxes[6][x[0xB]] ^ CustomAlgorithm.SBoxes[7][x[0x8]] ^ CustomAlgorithm.SBoxes[5][z[0x3]];
            Bits32ToInts(xCF, x, 0xC);
            _Kr[13] = (int)((CustomAlgorithm.SBoxes[4][x[0x8]] ^ CustomAlgorithm.SBoxes[5][x[0x9]] ^ CustomAlgorithm.SBoxes[6][x[0x7]] ^ CustomAlgorithm.SBoxes[7][x[0x6]] ^ CustomAlgorithm.SBoxes[4][x[0x3]]) & 0x1f);
            _Kr[14] = (int)((CustomAlgorithm.SBoxes[4][x[0xA]] ^ CustomAlgorithm.SBoxes[5][x[0xB]] ^ CustomAlgorithm.SBoxes[6][x[0x5]] ^ CustomAlgorithm.SBoxes[7][x[0x4]] ^ CustomAlgorithm.SBoxes[5][x[0x7]]) & 0x1f);
            _Kr[15] = (int)((CustomAlgorithm.SBoxes[4][x[0xC]] ^ CustomAlgorithm.SBoxes[5][x[0xD]] ^ CustomAlgorithm.SBoxes[6][x[0x3]] ^ CustomAlgorithm.SBoxes[7][x[0x2]] ^ CustomAlgorithm.SBoxes[6][x[0x8]]) & 0x1f);
            _Kr[16] = (int)((CustomAlgorithm.SBoxes[4][x[0xE]] ^ CustomAlgorithm.SBoxes[5][x[0xF]] ^ CustomAlgorithm.SBoxes[6][x[0x1]] ^ CustomAlgorithm.SBoxes[7][x[0x0]] ^ CustomAlgorithm.SBoxes[7][x[0xD]]) & 0x1f);
        }

        /**
        * Encrypt the given input starting at the given offset and place
        * the result in the provided buffer starting at the given offset.
        *
        * @param src        The plaintext buffer
        * @param srcIndex    An offset into src
        * @param dst        The ciphertext buffer
        * @param dstIndex    An offset into dst
        */
        internal int EncryptBlock(
            byte[] src,
            int srcIndex,
            byte[] dst,
            int dstIndex)
        {
            // process the input block
            // batch the units up into a 32 bit chunk and go for it
            // the array is in bytes, the increment is 8x8 bits = 64

            uint L0 = Pack.BE_To_UInt32(src, srcIndex);
            uint R0 = Pack.BE_To_UInt32(src, srcIndex + 4);

            uint[] result = new uint[2];
            CAST_Encipher(L0, R0, result);

            // now stuff them into the destination block
            Pack.UInt32_To_BE(result[0], dst, dstIndex);
            Pack.UInt32_To_BE(result[1], dst, dstIndex + 4);

            return BLOCK_SIZE;
        }

        /**
        * Decrypt the given input starting at the given offset and place
        * the result in the provided buffer starting at the given offset.
        *
        * @param src        The plaintext buffer
        * @param srcIndex    An offset into src
        * @param dst        The ciphertext buffer
        * @param dstIndex    An offset into dst
        */
        internal int DecryptBlock(
            byte[] src,
            int srcIndex,
            byte[] dst,
            int dstIndex)
        {
            // process the input block
            // batch the units up into a 32 bit chunk and go for it
            // the array is in bytes, the increment is 8x8 bits = 64
            uint L16 = Pack.BE_To_UInt32(src, srcIndex);
            uint R16 = Pack.BE_To_UInt32(src, srcIndex + 4);

            uint[] result = new uint[2];
            CAST_Decipher(L16, R16, result);

            // now stuff them into the destination block
            Pack.UInt32_To_BE(result[0], dst, dstIndex);
            Pack.UInt32_To_BE(result[1], dst, dstIndex + 4);

            return BLOCK_SIZE;
        }

        /**
        * The first of the three processing functions for the
        * encryption and decryption.
        *
        * @param D            the input to be processed
        * @param Kmi        the mask to be used from Km[n]
        * @param Kri        the rotation value to be used
        *
        */
        internal static uint F1(uint D, uint Kmi, int Kri)
        {
            uint I = Kmi + D;
            I = I << Kri | (I >> (32 - Kri));
            return ((CustomAlgorithm.SBoxes[0][(I >> 24) & 0xff] ^ CustomAlgorithm.SBoxes[1][(I >> 16) & 0xff]) - CustomAlgorithm.SBoxes[2][(I >> 8) & 0xff]) + CustomAlgorithm.SBoxes[3][I & 0xff];
        }

        /**
        * The second of the three processing functions for the
        * encryption and decryption.
        *
        * @param D            the input to be processed
        * @param Kmi        the mask to be used from Km[n]
        * @param Kri        the rotation value to be used
        *
        */
        internal static uint F2(uint D, uint Kmi, int Kri)
        {
            uint I = Kmi ^ D;
            I = I << Kri | (I >> (32 - Kri));
            return ((CustomAlgorithm.SBoxes[0][(I >> 24) & 0xff] - CustomAlgorithm.SBoxes[1][(I >> 16) & 0xff]) + CustomAlgorithm.SBoxes[2][(I >> 8) & 0xff]) ^ CustomAlgorithm.SBoxes[3][I & 0xff];
        }

        /**
        * The third of the three processing functions for the
        * encryption and decryption.
        *
        * @param D            the input to be processed
        * @param Kmi        the mask to be used from Km[n]
        * @param Kri        the rotation value to be used
        *
        */
        internal static uint F3(uint D, uint Kmi, int Kri)
        {
            uint I = Kmi - D;
            I = I << Kri | (I >> (32 - Kri));
            return ((CustomAlgorithm.SBoxes[0][(I >> 24) & 0xff] + CustomAlgorithm.SBoxes[1][(I >> 16) & 0xff]) ^ CustomAlgorithm.SBoxes[2][(I >> 8) & 0xff]) - CustomAlgorithm.SBoxes[3][I & 0xff];
        }

        /**
        * Does the 16 rounds to encrypt the block.
        *
        * @param L0    the LH-32bits of the plaintext block
        * @param R0    the RH-32bits of the plaintext block
        */
        internal void CAST_Encipher(uint L0, uint R0, uint[] result)
        {
            uint Lp = L0;        // the previous value, equiv to L[i-1]
            uint Rp = R0;        // equivalent to R[i-1]

            /*
            * numbering consistent with paper to make
            * checking and validating easier
            */
            uint Li = L0, Ri = R0;

            for (int i = 1; i <= _rounds; i++)
            {
                Lp = Li;
                Rp = Ri;

                Li = Rp;
                switch (i)
                {
                    case 1:
                    case 4:
                    case 7:
                    case 10:
                    case 13:
                    case 16:
                        Ri = Lp ^ F1(Rp, _Km[i], _Kr[i]);
                        break;
                    case 2:
                    case 5:
                    case 8:
                    case 11:
                    case 14:
                        Ri = Lp ^ F2(Rp, _Km[i], _Kr[i]);
                        break;
                    case 3:
                    case 6:
                    case 9:
                    case 12:
                    case 15:
                        Ri = Lp ^ F3(Rp, _Km[i], _Kr[i]);
                        break;
                }
            }

            result[0] = Ri;
            result[1] = Li;

            return;
        }

        internal void CAST_Decipher(uint L16, uint R16, uint[] result)
        {
            uint Lp = L16;        // the previous value, equiv to L[i-1]
            uint Rp = R16;        // equivalent to R[i-1]

            /*
            * numbering consistent with paper to make
            * checking and validating easier
            */
            uint Li = L16, Ri = R16;

            for (int i = _rounds; i > 0; i--)
            {
                Lp = Li;
                Rp = Ri;

                Li = Rp;
                switch (i)
                {
                    case 1:
                    case 4:
                    case 7:
                    case 10:
                    case 13:
                    case 16:
                        Ri = Lp ^ F1(Rp, _Km[i], _Kr[i]);
                        break;
                    case 2:
                    case 5:
                    case 8:
                    case 11:
                    case 14:
                        Ri = Lp ^ F2(Rp, _Km[i], _Kr[i]);
                        break;
                    case 3:
                    case 6:
                    case 9:
                    case 12:
                    case 15:
                        Ri = Lp ^ F3(Rp, _Km[i], _Kr[i]);
                        break;
                }
            }

            result[0] = Ri;
            result[1] = Li;

            return;
        }

        internal static void Bits32ToInts(uint inData, int[] b, int offset)
        {
            b[offset + 3] = (int)(inData & 0xff);
            b[offset + 2] = (int)((inData >> 8) & 0xff);
            b[offset + 1] = (int)((inData >> 16) & 0xff);
            b[offset] = (int)((inData >> 24) & 0xff);
        }

        internal static uint IntsTo32bits(int[] b, int i)
        {
            return (uint)(((b[i] & 0xff) << 24) |
                ((b[i + 1] & 0xff) << 16) |
                ((b[i + 2] & 0xff) << 8) |
                ((b[i + 3] & 0xff)));
        }
    }
}

using Long.Login.Database;
using Long.Login.Database.Entities;
using Long.Login.Database.Repositories;
using Long.Login.Managers;
using Long.Login.Network.Game.Packets;
using Long.Login.States;
using Long.Network.Packets;
using System.Text;

namespace Long.Login.Network.Login.Packets
{
    public abstract class LoaderEncryption
    {
        static byte[] Key1 = new byte[32] { 68, 101, 226, 42, 136, 112, 41, 93, 119, 214, 190, 131, 36, 138, 41, 70, 218, 115, 53, 197, 139, 196, 209, 31, 39, 219, 145, 17, 94, 194, 204, 219 };
        static byte[] Key2 = new byte[32] { 253, 8, 70, 229, 253, 183, 12, 140, 83, 52, 158, 214, 83, 162, 239, 120, 135, 243, 179, 113, 64, 203, 72, 95, 101, 187, 77, 116, 29, 254, 247, 175 };
        public static string Decrypt(byte[] data, byte size)
        {
            byte[] BufferOut = new byte[Math.Min((int)size, 32)];
            for (int x = 0; x < Math.Min((int)size, 32); x++)
            {
                BufferOut[x] = (byte)(Key1[x * 44 % 32] ^ data[x]);
                BufferOut[x] = (byte)(Key2[x * 99 % 32] ^ BufferOut[x]);
            }
            return System.Text.ASCIIEncoding.ASCII.GetString(BufferOut).Replace("\0", "");
        }
        public static string DecryptSerial(byte[] val)
        {
            for (int x = 0; x < val.Length; x++)
            {
                val[x] = (byte)(val[x] + 156);
            }
            return Encoding.Default.GetString(val).Replace("\0", "");
        }
    }
    public sealed class MsgAccount : MsgBase<LoginClient>
    {
        private static readonly ILogger logger = Log.ForContext<MsgAccount>();

        // Packet Properties
        public string Username { get; private set; }
        public string Password { get; private set; }
        public string Realm { get; private set; }
        public string Mac { get; private set; }
        public string MagicHash { get; private set; }
        public string MagicEffectHash { get; private set; }
        public string DLLHash { get; private set; }
        public int ComputerIdlen { get; private set; }
        public string ComputerId = "";

        /// <summary>
        ///     Decodes a byte packet into the packet structure defined by this message class.
        ///     Should be invoked to structure data from the client for processing. Decoding
        ///     follows TQ Digital's byte ordering rules for an all-binary protocol.
        /// </summary>
        /// <param name="bytes">Bytes from the packet processor or client socket</param>
        public override void Decode(byte[] bytes)
        {
            var reader = new PacketReader(bytes);
            Length = reader.ReadUInt16();
            Type = (PacketType)reader.ReadUInt16();

            Username = reader.ReadString(32).Replace("\0", "");
            reader.BaseStream.Seek(36, SeekOrigin.Current);


            byte Size = reader.ReadByte();
            byte[] passord = new byte[63];
            passord = reader.ReadBytes(63);
            Password = LoaderEncryption.Decrypt(passord, Size).Replace("\0", "");

            Realm = Encoding.Default.GetString(reader.ReadBytes(16)).Replace("\0", "");
            Mac = Encoding.Default.GetString(reader.ReadBytes(12));
            reader.BaseStream.Seek(136, SeekOrigin.Current);
            MagicEffectHash = Encoding.Default.GetString(reader.ReadBytes(33)).Replace("\0", "");
            MagicHash = Encoding.Default.GetString(reader.ReadBytes(33)).Replace("\0", "");
            DLLHash = Encoding.Default.GetString(reader.ReadBytes(33)).Replace("\0", "");

            ComputerIdlen = BitConverter.ToInt16(bytes, 465);
            byte[] Serial = new byte[ComputerIdlen];
            Buffer.BlockCopy(bytes, 467, Serial, 0, ComputerIdlen);
            ComputerId = LoaderEncryption.DecryptSerial(Serial).Replace(" ", "");
        }

        public override async Task ProcessAsync(LoginClient client)
        {
            LoginStatisticManager.IncreaseLogin();

            try
            {
#if !DEBUG
                CityLocation userLocation = LocationRepository.GetLocation(client.IpAddress);
#endif

                GameAccount gameAccount = AccountRepository.GetByUsername(Username);
                if (gameAccount == null)
                {
                    logger.Warning("Username {0} do not exist.", Username);
                    await client.DisconnectWithRejectionCodeAsync(MsgConnectEx.RejectionCode.InvalidAccount);
                    return;
                }

                if (!GameAccount.HashPassword(Password, gameAccount.Salt).Equals(gameAccount.Password))
                {
                    logger.Warning("User {0} has attempted to login with an invalid password.", Username);
                    await client.DisconnectWithRejectionCodeAsync(MsgConnectEx.RejectionCode.InvalidPassword);
                    return;
                }

                if (gameAccount.Flag != 0)
                {
                    logger.Warning("User {0} is locked.", Username);
                    await client.DisconnectWithRejectionCodeAsync(MsgConnectEx.RejectionCode.AccountBanned);
                    return;
                }

#if DEBUG
                //if (gameAccount.AuthorityId == 1)
                //{
                //    logger.Warning("User {0} non cooperator account.", Username);
                //    await client.DisconnectWithRejectionCodeAsync(MsgConnectEx.RejectionCode.NonCooperatorAccount);
                //    return;
                //}
#endif

                var realm = RealmManager.GetRealm(Realm);
                if (realm == null)
                {
                    logger.Warning("User {0} attempted to connecto to unexistent {1} realm.", Username, Realm);
                    await client.DisconnectWithRejectionCodeAsync(MsgConnectEx.RejectionCode.ServerDown);
                    return;
                }

                //if (!realm.IsProduction && gameAccount.AuthorityId == 1)
                //{
                //    logger.Warning("User {0} non cooperator account on not production realm.", Username);
                //    await client.DisconnectWithRejectionCodeAsync(MsgConnectEx.RejectionCode.NonCooperatorAccount);
                //    return;
                //}

                byte vipLevel = 0;
                var vipData = VipRepository.GetAccountVip(gameAccount.Id);
                if (vipData != null)
                {
                    vipLevel = vipData.VipLevel;
                }

                client.AccountID = (uint)gameAccount.Id;
                client.Username = gameAccount.UserName;

#if !DEBUG
                await LoginRecordRepository.LoginRcdAsync(client, userLocation, true);
#endif

                User user = UserManager.GetUser(client.AccountID);
                if (user != null)
                {
                    // duplicated login request
                    logger.Warning("User {0} is already awaiting for a login response.", Username);
                    await client.DisconnectWithRejectionCodeAsync(MsgConnectEx.RejectionCode.PleaseTryAgainLater);
                    return;
                }

                user = new User(client, gameAccount, realm);
                UserManager.AddUser(user);

                await realm.Client.SendAsync(new MsgLoginUserExchange
                {
                    Data = new MsgLoginUserExchange.LoginExchangeData
                    {
                        AccountId = client.AccountID,
                        AuthorityId = (ushort)gameAccount.AuthorityId,
                        IpAddress = client.IpAddress,
                        Request = client.Guid.ToString(),
                        VipLevel = vipLevel
                    }
                });
            }
            catch (Exception ex)
            {
                logger.Error(ex, "Error on MsgAccount processing! {0}", ex.Message);
                if (client.Socket.Connected)
                {
                    await client.DisconnectWithRejectionCodeAsync(MsgConnectEx.RejectionCode.PleaseTryAgainLater);
                }
            }
        }

        

        /// <summary>
        ///     Decrypts the password from read in packet bytes for the <see cref="Decode" />
        ///     method. Trims the end of the password string of null terminators.
        /// </summary>
        /// <param name="buffer">Bytes from the packet buffer</param>
        /// <param name="seed">Seed for generating RC5 keys</param>
        /// <returns>Returns the decrypted password string.</returns>
        private string DecryptPassword(byte[] buffer, uint seed)
        {
            // debug purposes
            byte[] pSeed =
            {
                46, 22, 32, 87, 95, 48, 8, 2, 4, 34, 59, 83, 21, 2, 243, 1, 1, 2, 80, 37, 202, 31, 99, 75, 7, 4, 6, 23, 100, 221, 82, 134
            };
            int length = pSeed.Length;
            for (int x = 0; x < buffer.Length; x++)
            {
                if (buffer[x] != 0)
                {
                    buffer[x] ^= pSeed[(x * 48 % 32) % length];
                    buffer[x] ^= pSeed[(x * 24 % 16) % length];
                    buffer[x] ^= pSeed[(x * 12 % 8) % length];
                    buffer[x] ^= pSeed[(x * 6 % 4) % length];
                }
            }
            return Encoding.ASCII.GetString(buffer).Trim('\0');
        }
    }
}

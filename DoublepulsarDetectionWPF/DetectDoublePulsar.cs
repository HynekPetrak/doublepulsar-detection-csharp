using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Net.Sockets;
using NLog;

namespace DoublepulsarDetectionWPF {
    class DetectDoublePulsar {

        Logger _l = LogManager.GetCurrentClassLogger();

        public DetectDoublePulsar() {

        }
        byte[] INT2LE(UInt32 data) {
            byte[] b = new byte[4];
            b[0] = (byte)data;
            b[1] = (byte)(((uint)data >> 8) & 0xFF);
            b[2] = (byte)(((uint)data >> 16) & 0xFF);
            b[3] = (byte)(((uint)data >> 24) & 0xFF);
            return b;
        }

        UInt32 LE2INT(byte[] data) {
            UInt32 b;
            b = data[3];
            b <<= 8;
            b += data[2];
            b <<= 8;
            b += data[1];
            b <<= 8;
            b += data[0];
            return b;
        }

        public byte[] Slice(byte[] data, int index, int length) {
            byte[] result = new byte[length];
            Array.Copy(data, index, result, 0, length);
            return result;
        }
        static byte[] Hex2Binary(string hexvalue) {
            byte[] binaryval = new byte[hexvalue.Length/2];
            for (int i = 0; i < hexvalue.Length; i+=2) {
                string byteString = hexvalue.Substring(i, 2);
                byte b = Convert.ToByte(byteString, 16);
                binaryval[i>>1] = b;
            }
            return binaryval;
        }

        byte[] negotiate_protocol_request = Hex2Binary("00000085ff534d4272000000001853c00000000000000000000000000000fffe00004000006200025043204e4554574f524b2050524f4752414d20312e3000024c414e4d414e312e30000257696e646f777320666f7220576f726b67726f75707320332e316100024c4d312e325830303200024c414e4d414e322e3100024e54204c4d20302e313200");
        byte[] session_setup_request = Hex2Binary("00000088ff534d4273000000001807c00000000000000000000000000000fffe000040000dff00880004110a000000000000000100000000000000d40000004b000000000000570069006e0064006f007700730020003200300030003000200032003100390035000000570069006e0064006f007700730020003200300030003000200035002e0030000000");
        byte[] tree_connect_request = Hex2Binary("00000060ff534d4275000000001807c00000000000000000000000000000fffe0008400004ff006000080001003500005c005c003100390032002e003100360038002e003100370035002e003100320038005c00490050004300240000003f3f3f3f3f00");
        byte[] trans2_session_setup = Hex2Binary("0000004eff534d4232000000001807c00000000000000000000000000008fffe000841000f0c0000000100000000000000a6d9a40000000c00420000004e0001000e000d0000000000000000000000000000");

        Object print_lock = new object();

        //void Run(int threads = 1, string ip, string net, int timeout, bool uninstall) {
        //    Semaphore semaphore = new Semaphore(0, threads);

        //}

        // https://zerosum0x0.blogspot.com/2017/04/doublepulsar-initial-smb-backdoor-ring.html
        UInt32 calculate_doublepulsar_xor_key(UInt32 s) {
            UInt32 x;
            x = (2 * s ^ (((s & 0xff00 | (s << 16)) << 8) | (((s >> 16) | s & 0xff0000) >> 8)));
            x = x & 0xffffffff;  // this line was added just to truncate to 32 bits
            return x;
        }

        // The arch is adjacent to the XOR key in the SMB signature
        string calculate_doublepulsar_arch(UInt64 s) {
            if ((s & 0xffffffff00000000) == 0) {
                return "x86 (32-bit)";
            } else {
                return "x64 (64-bit)";
            }
        }

        void print_status(string ip, string message) {
            _l.Debug($"[*] [{ip}] {message}");
        }

        public void check_ip(string ip, out int infected, out int cleaned, int timeout = 5, bool verbose = false, bool uninstall = false) {
            byte[] buf = new byte[1024];
            byte[] session_setup_response;
            infected = -1;
            cleaned = 0;

            // Connect to socket
            Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            try {
                s.ReceiveTimeout = timeout * 1000;
                s.SendTimeout = timeout * 1000;

                s.Connect(ip, 445);

                // Send/receive negotiate protocol request
                if (verbose)
                    print_status(ip, "Sending negotiation protocol request");
                s.Send(negotiate_protocol_request);
                s.Receive(buf, 1024, SocketFlags.None);

                // Send/receive session setup request
                if (verbose)
                    print_status(ip, "Sending session setup request");
                s.Send(session_setup_request);
                s.Receive(buf, 1024, SocketFlags.None);
                session_setup_response = buf;

                // Extract user ID from session setup response
                byte[] user_id = new byte[2];
                user_id[0] = session_setup_response[32];
                user_id[1] = session_setup_response[33];
                if (verbose)
                    print_status(ip, $"User ID = {user_id[0],2:X}{user_id[1],2:X}");

                // Replace user ID in tree connect request packet
                byte[] modified_tree_connect_request = tree_connect_request.ToArray();
                modified_tree_connect_request[32] = user_id[0];
                modified_tree_connect_request[33] = user_id[1];
                //modified_tree_connect_request = "".join(modified_tree_connect_request);

                // Send tree connect request
                if (verbose)
                    print_status(ip, "Sending tree connect");
                s.Send(modified_tree_connect_request);
                s.Receive(buf, 1024, SocketFlags.None);
                byte[] tree_connect_response = buf;

                // Extract tree ID from response
                byte[] tree_id = new byte[2];
                tree_id[0] = tree_connect_response[28];
                tree_id[1] = tree_connect_response[29];
                if (verbose)
                    print_status(ip, $"Tree ID = {tree_id[0],2:X}{tree_id[1],2:X}");

                // Replace tree ID and user ID in trans2 session setup packet
                byte[] modified_trans2_session_setup = trans2_session_setup.ToArray();
                modified_trans2_session_setup[28] = tree_id[0];
                modified_trans2_session_setup[29] = tree_id[1];
                modified_trans2_session_setup[32] = user_id[0];
                modified_trans2_session_setup[33] = user_id[1];
                //modified_trans2_session_setup = "".join(modified_trans2_session_setup);

                // Send trans2 sessions setup request
                if (verbose)
                    print_status(ip, "Sending trans2 session setup - ping command");
                s.Send(modified_trans2_session_setup);
                s.Receive(buf, 1024, SocketFlags.None);
                byte[] final_response = buf;

                // Check for 0x51 response to indicate DOUBLEPULSAR infection
                if (final_response[34] == 0x51) {
                    byte[] signature = Slice(final_response, 18, 4);
                    UInt32 signature_long = LE2INT(signature);
                    UInt32 key = calculate_doublepulsar_xor_key(signature_long);
                    string arch = calculate_doublepulsar_arch(signature_long);
                    lock (print_lock) {
                        _l.Error($"[+] [{ip}] DOUBLEPULSAR SMB IMPLANT DETECTED!!! Arch: {arch}, XOR Key: {key,4:X}");
                        infected = 1;
                    }
                    if (uninstall) {
                        // Update MID and op code via timeout
                        modified_trans2_session_setup = modified_trans2_session_setup.ToArray();
                        modified_trans2_session_setup[34] = 0x42;
                        modified_trans2_session_setup[49] = 0x0e;
                        modified_trans2_session_setup[50] = 0x69;
                        modified_trans2_session_setup[51] = 0x00;
                        modified_trans2_session_setup[52] = 0x00;
                        //modified_trans2_session_setup = "".join(modified_trans2_session_setup);

                        if (verbose)
                            print_status(ip, "Sending trans2 session setup - uninstall/burn command");
                        s.Send(modified_trans2_session_setup);
                        s.Receive(buf, 1024, SocketFlags.None);

                        byte[] uninstall_response = buf;
                        if (uninstall_response[34] == 0x52) {
                            lock (print_lock) {
                                _l.Fatal($"[+] [{ip}] DOUBLEPULSAR uninstall successful");
                                cleaned = 1;
                            }
                        }
                    }
                } else {

                    lock (print_lock) {
                        _l.Info($"[-] [{ip}] No presence of DOUBLEPULSAR SMB implant");
                        infected = 0;
                    }
                }
                
            } catch(Exception ex) {
                _l.Warn($"[*] [{ip}] Exception occured: {ex.Message}");
            } finally {
                s.Close();
            }

        }
    }
}


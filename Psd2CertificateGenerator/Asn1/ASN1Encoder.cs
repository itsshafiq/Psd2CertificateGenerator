using System.IO;
using System.Security.Cryptography;

namespace Psd2CertificateGenerator.Asn1
{
    public class Asn1Encoder
    {
        private static void WriteLength(BinaryWriter stream, int length)
        {
            // Short form
            if (length < 0x80)
            {
                stream.Write((byte)length);
                return;
            }
            
            // Long form
            var temp = length;
            var bytesRequired = 0;
            while (temp > 0)
            {
                temp >>= 8;
                bytesRequired++;
            }
            stream.Write((byte)(bytesRequired | 0x80));
            for (var i = bytesRequired - 1; i >= 0; i--)
            {
                stream.Write((byte)(length >> (8 * i) & 0xff));
            }
        }

        public static byte[] IntegerBigEndian(byte[] value)
        {
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x02); // INTEGER

                var prefixZeros = 0;
                for (var i = 0; i < value.Length; i++)
                {
                    if (value[i] != 0) break;
                    prefixZeros++;
                }
                if (value.Length == prefixZeros) // all zeros
                {
                    WriteLength(writer, 1);
                    writer.Write((byte)0);
                }
                else
                {
                    if (value[prefixZeros] > 0x7f)
                    {
                        WriteLength(writer, value.Length - prefixZeros + 1);
                        writer.Write((byte)0);
                    }
                    else
                    {
                        WriteLength(writer, value.Length - prefixZeros);
                    }
                    for (var i = prefixZeros; i < value.Length; i++)
                    {
                        writer.Write(value[i]);
                    }
                }

                return stream.ToArray();
            }
        }

        public static byte[] BitString(byte numberOfUnusedBits, byte[] buffer)
        {
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x03); // BIT STRING

                WriteLength(writer, buffer.Length + 1);
                writer.Write(numberOfUnusedBits);
                writer.Write(buffer);

                return stream.ToArray();
            }
        }

        public static byte[] OctetString(byte[] buffer)
        {
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x04); // OCTET STRING

                WriteLength(writer, buffer.Length);
                writer.Write(buffer);

                return stream.ToArray();
            }
        }

        private static byte[] EncodedNull = new byte[] {
                0x05, // NULL
                0x00
            };
        public static byte[] Null()
        {
            return EncodedNull;
        }

        public static byte[] ObjectIdentifier(string oid)
        {
            return CryptoConfig.EncodeOID(oid);
        }

        public static byte[] Utf8String(string value)
        {
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x0C); // UTF8STRING

                var buffer = System.Text.Encoding.UTF8.GetBytes(value);
                WriteLength(writer, buffer.Length);
                writer.Write(buffer);

                return stream.ToArray();
            }
        }

        public static byte[] Sequence(params byte[][] values)
        {
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE

                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    foreach (var value in values)
                    {
                        innerWriter.Write(value);
                    }
                    var valuesLength = (int)innerStream.Length;
                    WriteLength(writer, valuesLength);
                    writer.Write(innerStream.GetBuffer(), 0, valuesLength);
                }
                return stream.ToArray();
            }
        }

    }
}

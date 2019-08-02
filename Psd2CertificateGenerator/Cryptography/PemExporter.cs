using Psd2CertificateGenerator.Asn1;
using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Psd2CertificateGenerator.Cryptography
{
    public class PemExporter
    {
        private static Regex Base64PEMLineBreaks = new Regex(".{1,64}");
        private const string OID_rsaEncryption = "1.2.840.113549.1.1.1";

        
        public static string ToPem(string label, byte[] buffer)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"-----BEGIN {label.ToUpper()}-----");
            sb.AppendLine(string.Join("\n", Base64PEMLineBreaks.Matches(Convert.ToBase64String(buffer))));
            sb.AppendLine($"-----END {label.ToUpper()}-----");
            return sb.ToString();
        }

        public static string ExportPublicKeyPKCS1(RSA rsa)
        {
            var parameters = rsa.ExportParameters(false);
            return ToPem("PUBLIC KEY", Asn1Encoder.Sequence(
                Asn1Encoder.Sequence( // AlgorithmIdentifier
                    Asn1Encoder.ObjectIdentifier(OID_rsaEncryption), // algorithm
                    Asn1Encoder.Null() // parameters
                ),
                Asn1Encoder.BitString(0,
                    Asn1Encoder.Sequence(
                        Asn1Encoder.IntegerBigEndian(parameters.Modulus),
                        Asn1Encoder.IntegerBigEndian(parameters.Exponent)
                    )
                )
            ));
        }


        public static string ExportPrivateKeyPKCS8(RSA rsa)
        {
            var parameters = rsa.ExportParameters(true);
            return ToPem("RSA PRIVATE KEY", Asn1Encoder.Sequence(
                Asn1Encoder.IntegerBigEndian(new byte[] { 0x00 }), // Version
                Asn1Encoder.Sequence( // AlgorithmIdentifier
                    Asn1Encoder.ObjectIdentifier(OID_rsaEncryption), // algorithm
                    Asn1Encoder.Null() // parameters
                ),
                Asn1Encoder.OctetString(
                    Asn1Encoder.Sequence(
                        Asn1Encoder.IntegerBigEndian(new byte[] { 0x00 }), // Version
                        Asn1Encoder.IntegerBigEndian(parameters.Modulus),
                        Asn1Encoder.IntegerBigEndian(parameters.Exponent),
                        Asn1Encoder.IntegerBigEndian(parameters.D),
                        Asn1Encoder.IntegerBigEndian(parameters.P),
                        Asn1Encoder.IntegerBigEndian(parameters.Q),
                        Asn1Encoder.IntegerBigEndian(parameters.DP),
                        Asn1Encoder.IntegerBigEndian(parameters.DQ),
                        Asn1Encoder.IntegerBigEndian(parameters.InverseQ)
                    )
                )
            ));
        }

    }
}

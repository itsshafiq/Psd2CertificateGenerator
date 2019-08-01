using System;

namespace Psd2CertificateGenerator.CLI
{
    class Program
    {
        static void Main(string[] args)
        {
            var psd2c = PSD2Certificate.createRSAKeysAndCertificate(new PSD2CertificateParameters
            {
                CertificateType = PSD2CertificateType.QWAC,
                IssuerDnsName = "payoneer.com",
                Issuer = new PSD2CertificateIssuerParameters
                {
                    EmailAddress = "support@payoneer.com",
                    CommonName = "Payoneer PSD2 Sandbox",
                    OrganizationUnit = "Payoneer EU",
                    Organization = "Payoneer",
                    Locality = "Gibraltar",
                    State = "Gibraltar",
                    Country = "GI"
                },
                Subject = new PSD2CertificateSubjectParameters {
                    CommonName = "TPP Test QWAC",
                    OrganizationIdentifier = "PSDIL-PAY-010101",
                    Organization = "Eli Inc",
                    Country = "IL"
                },
                RetentionPeriod = 20,
                Roles = PSD2Roles.PSP_AI | PSD2Roles.PSP_PI
            });

            Console.WriteLine(psd2c.PublicKey);
            Console.WriteLine(psd2c.PrivateKey);
            Console.WriteLine(psd2c.Certificate);
        }
    }
}

using CommandLine;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Psd2CertificateGenerator.CLI
{
    class Program
    {
        private class Options
        {
            [Option('f', "file", HelpText = "Output filename(s) (e.g. file.crt, file.key, file.pub), if omitted then stdout")]
            public string Filename { get; set; }

            // PSD2 Certificate

            [Option('t', "type", Default = PSD2CertificateType.QWAC ,HelpText = "The certificate type")]
            public PSD2CertificateType Type { get; set; }
            [Option('r', "roles", Default = PSD2Roles.PSP_AI_PSP_PI, HelpText = "The PSD2 roles")]
            public PSD2Roles Roles { get; set; }

            // Issuer

            [Option('d', "issuer-dns", Default = "payoneer.com", HelpText = "The Issuer's DNS name")]
            public string IssuerDNSName { get; set; }
            [Option('e', "issuer-email", Default = "support@payoneer.com", HelpText = "The Issuer's Email address")]
            public string IssuerEmailAddress { get; set; }
            [Option('m', "issuer-cn", Default = "Payoneer PSD2 Sandbox", HelpText = "The Issuer's Common name")]
            public string IssuerCommonName { get; set; }
            [Option('o', "issuer-o", Default = "Payoneer", HelpText = "The Issuer's organization name")]
            public string IssuerOrganization { get; set; }
            [Option('u', "issuer-ou", Default = "Payoneer EU", HelpText = "The Issuer's organization unit name")]
            public string IssuerOrganizationUnit { get; set; }
            [Option('l', "issuer-l", Default = "Gibraltar", HelpText = "The Issuer's locality")]
            public string IssuerLocality { get; set; }
            [Option('s', "issuer-s", HelpText = "The Issuer's state")]
            public string IssuerState { get; set; }
            [Option('y', "issuer-c", Default = "GI", HelpText = "The Issuer's country")]
            public string IssuerCountry { get; set; }

            // Subject

            [Option('n', "name", Required = true, HelpText = "The TPP's name")]
            public string TPPName { get; set; }
            [Option('a', "auth", Required = true, HelpText = "The TPP's PSD2 Authentication Number")]
            public string TPPPSD2AuthenticationNumber { get; set; }
            [Option('c', "country", Required = true, HelpText = "The TPP's Country")]
            public string TPPCountry { get; set; }

            // NCA

            [Option("nca-name", Default = "Payoneer", HelpText = "The approving NCA's name")]
            public string NCAName { get; set; }
            [Option("nca-id", Default = "IL-PAY", HelpText = "The approving NCA's id")]
            public string NCAId { get; set; }
        }

        static void Run(Options o)
        {
            var psd2c = PSD2Certificate.createRSAKeysAndCertificate(new PSD2CertificateParameters
            {
                CertificateType = o.Type,
                IssuerDnsName = o.IssuerDNSName,
                Issuer = new PSD2CertificateIssuerParameters
                {
                    EmailAddress = o.IssuerEmailAddress,
                    CommonName = o.IssuerCommonName,
                    OrganizationUnit = o.IssuerOrganizationUnit,
                    Organization = o.IssuerOrganization,
                    Locality = o.IssuerLocality,
                    State = o.IssuerState,
                    Country = o.IssuerCountry
                },
                Subject = new PSD2CertificateSubjectParameters
                {
                    CommonName = "TPP Test " + o.Type.ToString(),
                    OrganizationIdentifier = o.TPPPSD2AuthenticationNumber,
                    Organization = o.TPPName,
                    Country = o.TPPCountry
                },
                RetentionPeriod = 20,
                Roles = o.Roles,
                NcaId = o.NCAId,
                NcaName = o.NCAName
            });

            if (string.IsNullOrEmpty(o.Filename))
            {
                Console.WriteLine(psd2c.PublicKey);
                Console.WriteLine(psd2c.PrivateKey);
                Console.WriteLine(psd2c.Certificate);
            }
            else
            {
                System.IO.File.WriteAllText(System.IO.Path.Combine(Environment.CurrentDirectory, o.Filename + ".pub"), psd2c.PublicKey);
                System.IO.File.WriteAllText(System.IO.Path.Combine(Environment.CurrentDirectory, o.Filename + ".key"), psd2c.PrivateKey);
                System.IO.File.WriteAllText(System.IO.Path.Combine(Environment.CurrentDirectory, o.Filename + ".crt"), psd2c.Certificate);
            }
        }

        static void Main(string[] args)
        {
            Parser.Default.ParseArguments<Options>(args).WithParsed(Run);
        }
    }
}

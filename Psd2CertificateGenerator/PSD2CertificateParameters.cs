using System;
using System.ComponentModel.DataAnnotations;

namespace Psd2CertificateGenerator
{
    public enum PSD2CertificateType
    {
        QWAC,
        QsealC
    }

    [Flags]
    public enum PSD2Roles
    {
        None = 0,
        PSP_AI = 0x01,
        PSP_PI = 0x02,
        PSP_AI_PSP_PI = PSP_AI | PSP_PI,
        PSP_IC = 0x04,
        PSP_AI_PSP_PI_PSP_IC = PSP_AI | PSP_PI | PSP_IC,
        PSP_AS = 0x08,
        All = PSP_AI | PSP_PI | PSP_IC | PSP_AS,
    }

    public class PSD2CertificateIssuerParameters
    {
        [EmailAddress]
        public string EmailAddress { get; set; }
        public string CommonName { get; set; }
        public string Organization { get; set; }
        public string OrganizationUnit { get; set; }
        public string Locality { get; set; }
        public string State { get; set; }
        [RegularExpression("^[A-Z]{2}$", ErrorMessage = "Country should be 2 uppercase English letters (ISO 3166)")]
        public string Country { get; set; }
    }

    public class PSD2CertificateSubjectParameters
    {
        [Required(AllowEmptyStrings = false, ErrorMessage = "The Subject.CommonName field is required"),
            RegularExpression("^[^=/,]*$", ErrorMessage = "CommonName should not include the following characters [=/,]")]
        public string CommonName { get; set; }
        [Required(AllowEmptyStrings = false, ErrorMessage = "The Subject.Organization field is required"),
            RegularExpression("^[^=/,]*$", ErrorMessage = "Organization should not include the following characters [=/,]")]
        public string Organization { get; set; }
        [Required(AllowEmptyStrings = false, ErrorMessage = "The Subject.Country field is required"),
            RegularExpression("^[A-Z]{2}$", ErrorMessage = "Country should be 2 uppercase English letters (ISO 3166)")]
        public string Country { get; set; }
        [Required(AllowEmptyStrings = false, ErrorMessage = "The Subject.OrganizationIdentifier field is required"),
            RegularExpression("^PSD[A-Z]{2}-[A-Z]{2,8}-.*$", ErrorMessage = "OrganizationIdentifier should be in the format PSDCC-ZZZ-###### (C=country_iso_3166, Z=nca_id, #=nca_given_id)")]
        public string OrganizationIdentifier { get; set; }
    }

    public class PSD2CertificateParameters
    {
        public PSD2CertificateIssuerParameters Issuer { get; set; }
        public string IssuerDnsName { get; set; }
        public PSD2CertificateSubjectParameters Subject { get; set; }
        public PSD2Roles Roles { set; get; }
        public PSD2CertificateType CertificateType { get; set; }
        public byte RetentionPeriod { get; set; } = 20;
        [Required(AllowEmptyStrings = false, ErrorMessage = "The NcaName field is required"),
            MaxLength(256, ErrorMessage = "NcaName must not be longer than 256 characters")]
        public string NcaName { get; set; }
        [Required(AllowEmptyStrings = false, ErrorMessage = "The NcaId field is required"),
            RegularExpression("^[A-Z]{2}-[A-Z]{2,8}$", ErrorMessage = "NcaId should be in the format CC-ZZZ (C=country_iso_3166, Z=nca_id)"),
            MaxLength(256, ErrorMessage = "NcaId must not be longer than 256 characters")]
        public string NcaId { get; set; }
    }
}

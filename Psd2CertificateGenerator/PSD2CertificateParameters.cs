﻿using System;
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
        PSP_AI = 0x01,
        PSP_PI = 0x02,
        PSP_IC = 0x04,
        PSP_AS = 0x08
    }

    public class PSD2CertificateIssuerParameters
    {
        public string EmailAddress { get; set; }
        public string CommonName { get; set; }
        public string Organization { get; set; }
        public string OrganizationUnit { get; set; }
        public string Locality { get; set; }
        public string State { get; set; }
        public string Country { get; set; }
    }

    public class PSD2CertificateSubjectParameters
    {
        [Required(AllowEmptyStrings = false, ErrorMessage = "The CommonName field is required"),
            RegularExpression("^[^=/,]*$", ErrorMessage = "CommonName should not include the following characters [=/,]")]
        public string CommonName { get; set; }
        [Required(AllowEmptyStrings = false, ErrorMessage = "The Organization field is required"),
            RegularExpression("^[^=/,]*$", ErrorMessage = "Organization should not include the following characters [=/,]")]
        public string Organization { get; set; }
        [Required(AllowEmptyStrings = false, ErrorMessage = "The Country field is required"),
            RegularExpression("^[A-Z]{2}$", ErrorMessage = "Country should be 2 uppercase English letters")]
        public string Country { get; set; }
        [Required(AllowEmptyStrings = false, ErrorMessage = "The OrganizationIdentifier field is required"),
            RegularExpression("^PSD[A-Z]{2}-[A-Z]{2,8}-.*$", ErrorMessage = "OrganizationIdentifier should be in the format PSDCC-ZZZ-###### (C=country, Z=nca_id, #=nca_given_id)")]
        public string OrganizationIdentifier { get; set; }
    }

    public class PSD2CertificateParameters
    {
        public PSD2CertificateIssuerParameters Issuer { get; set; }
        public string IssuerDnsName { get; set; }
        public PSD2CertificateSubjectParameters Subject { get; set; }
        public PSD2Roles Roles { set; get; }
        public PSD2CertificateType CertificateType { get; set; }
        public byte RetentionPeriod { get; set; } = 20; // default
    }
}
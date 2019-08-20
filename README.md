# Generate Test PSD2 Certificates

Based on https://www.etsi.org/deliver/etsi_ts/119400_119499/119495/01.03.02_60/ts_119495v010302p.pdf

# Getting started

* Make sure you have .Net Core 2.2 installed.
1. **Clone** repository (`git clone https://github.com/payoneer/Psd2CertificateGenerator.git`)<br/>
Inside the repo folder
1. **Build**<br/>
`dotnet build`
1. **Run**. For example:<br/>
`dotnet run --project=Psd2CertificateGenerator.CLI -n "My TPP Name" -a "PSDXX-YYY-ZZZZZZ" --country FR`
* You can run `dotnet run --project=Psd2CertificateGenerator.CLI` to see all the possible arguments.

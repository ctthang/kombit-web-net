# kombit-web-net
Sample .NET Framework 4.8 web application using Context Handler.

Document Reference: D.03.08.00010

## Introduction

This guide describes how to configure the sample .Net web application using Context Handler for login.

In the KOMBIT Støttesystemer information model, a web application that authenticates users based on an assertion issued by Context Handler (CH) is referred to as a Brugervendt system. In the following guide the terms `Brugervendt system` and `web application` will be used interchangeably.

After completing this guide, the .Net-based sample web application will be configured and ready to be used.

It is assumed that the reader is a .Net-developer knowledgeable in the technologies used to develop this .Net-based sample, including:

* C#
* .NET Framework 4.8
* Microsoft Windows Server Operating System
* Microsoft Internet Information Systems (IIS)
* HTTP and HTTPS
* X509v3 Certificates

## Overview of the Sample .NET Web Application

The .Net sample web application is based on the open source project OIOSAML.Net

The WebsiteDemo in OIOSAML.Net is used to demonstrate how to send a SAML2.0 AuthRequest, how to receive, and how to process a SAML2.0 response containing a SAML2.0 assertion. 

This guide explains how to configure the sample web application (websitedemo) based on a SAML2.0 metadata document from the identity provider with which the sample web application will be used. In this sample, the identity provider is the `Context Handler`.

In this guide the metadata-file for the KOMBIT Støttesystemer Context Handler in the project environment is used.

## Setup
To use this sample do the following:

1. Clone or unpack the repository, for example to `E:\Github\kombit-web-net`.
2. Open `Kombit.Samples.CH.WebsiteDemo.sln` in Visual Studio 2022 or later, restore the NuGet packages, and build the solution.
3. Make sure an SSL certificate that covers the DNS name `claimapp.eksterntest-stoettesystemerne.dk` is present in `LocalMachine\My` certificate store.
4. Open the Hosts-file, and map the DNS name `claimapp.eksterntest-stoettesystemerne.dk` to localhost.
5. Create a new IIS web application:
	1. The `Site name` should be `claimapp.eksterntest-stoettesystemerne.dk`
	2. The `Physical path` should be the local `Kombit.Samples.CH.WebsiteDemo` project directory
	3. The `Binding type` should be `HTTPS`
	4. The `Host name` should be `claimapp.eksterntest-stoettesystemerne.dk`
	5. Select an appropriate SSL certificate, that matches the host name chosen in the previous step
6. Grant the application pool identity for the web application read and execute permissions to the repository directory.
7. Import the certificate `Certificates\saml.claimapp.eksterntest-stoettesystemerne.dk.p12` to `LocalMachine\My`.
8. Assign the application pool identity for the web application read permissions to the private key for the certificate imported in the previous step.
9. Open a browser and point it to the configured local HTTPS site.
10. Click the **Go to My Page** link to log in using the Context Handler.

## BST token exchange and NTS service call

After a successful Context Handler login, `MyPage.aspx` reads the bootstrap token from the SAML assertion. The **Exchange BST Token for SOSI ID Card** button then:

1. Parses the bootstrap token.
2. Signs and sends a BST2SOSI request to the configured STS endpoint.
3. Stores the returned `UserIdCard` in ASP.NET session state.
4. Displays the issued assertion and enables the service-call button.

The **Call Service** button uses the generated WCF contract in `NtsReference.cs`. `STS\ServiceCaller.cs` creates a SOAP 1.1 `BasicHttpBinding` channel and adds the DGWS headers explicitly with SEAL.NET:

* `IdCardHeader(idCard)` carries the STS-issued ID card.
* `XmlHeader(dgwsHeader)` carries the DGWS header.
* `SealEndpointBehavior` validates service responses and reports DGWS errors.

The NTS test endpoint is configured in `Kombit.Samples.CH.WebsiteDemo\Web.config`:

```xml
<add key="ntsServiceEndpoint" value="http://test1.ekstern-test.nspop.dk:8080/nts/service-01172024" />
<add key="ntsServiceEndpointDnsIdentity" value="" />
```

Port `8080` uses HTTP in this test configuration. Do not change the endpoint to HTTPS unless the NSP environment provides a TLS-enabled endpoint and port.

`NtsReference.cs` was generated from:

`http://test1.ekstern-test.nspop.dk:8080/nts/service-01172024?wsdl`

If the WSDL changes, regenerate the reference with the .NET Framework 4.8 `SvcUtil.exe` tool and review the generated code before replacing the existing file. Do not manually edit the generated file.

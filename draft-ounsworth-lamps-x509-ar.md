---
title: X.509 Certificate Extensions for Attestation Results
abbrev: X.509 Cert Extensions for ARs
docname: draft-ounsworth-lamps-x509-ar-latest
category: std
consensus: true
submissiontype: IETF

ipr: trust200902
area: Security
workgroup: RATS
keyword: Internet-Draft

stand_alone: yes
pi:
  rfcedstyle: yes
  toc: yes
  tocindent: yes
  sortrefs: yes
  symrefs: yes
  strict: yes
  comments: yes
  inline: yes
  text-list-symbols: o-*+
  compact: yes
  subcompact: yes
  consensus: false

author:
  -
    ins: M. Ounsworth
    name: Mike Ounsworth
    org: Entrust Limited
    abbrev: Entrust
    street: 2500 Solandt Road – Suite 100
    city: Ottawa, Ontario
    country: Canada
    code: K2K 3G5
    email: mike.ounsworth@entrust.com
  -
    ins: M. Wiseman
    name: Monty Wiseman
    org: Beyond Identity
    country: USA
    email: monty.wiseman@beyondidentity.com
  -
    name: Hannes Tschofenig
    organization: University of Applied Sciences Bonn-Rhein-Sieg
    abbrev: H-BRS
    email: Hannes.Tschofenig@gmx.net
 -
    fullname: Tirumaleswar Reddy
    organization: Nokia
    city: Bangalore
    region: Karnataka
    country: India
    email: "kondtir@gmail.com"
-
    name: Ned Smith
    organization: Intel Corporation
    country: USA
    email: ned.smith@intel.com
 -
normative:
  RFC2119:
  RFC5280:
  RFC9334:
  I-D.ietf-rats-eat:

informative:
  RFC5912:
  RFC9344:
  RFC6268:

--- abstract

This document defines extensions for X.509 certificates to include attestation results as part of the certificate's content. The primary use case for these extensions is in the context of Certificate Signing Request (CSR) attestation, where claims about the trustworthiness of an Attester are conveyed to the Certification Authority (CA) as part of the CSR process. These extensions enable the CA to appraise the submitted evidence and embed attestation results into the issued certificate. This allows Relying Parties to evaluate the Attester's trustworthiness consistently and efficiently, supporting scalable policies for verification in environments with diverse attestation technologies.

--- middle

# Introduction

TBD.


~~~ aasvg
                          .-----------------.
                          |                 | Compare Evidence
                          |     Verifier    | against Appraisal
                          |                 | Policy
                          '------------+----'
                               ^       |
                      Evidence |       | Attestation
                        (2)    |       | Result (3)
                               |       v
.------------.            .----|-------|----.                .-----.
|            +----------->|----'       '--->|--------------->|     |
| HSM        | Evidence   | Registration    | CSR with       | CA  |
| (Attester) | in CSR (1) | Authority       | Attestation    |     |
|            |            | (Relying Party) | Result (4)     |     |
'------------'            '-----------------'                '-----'
    ^     ^                                                     |
    |     |    X.509 Certificate with Attestation Result (5)    |
    |     +-----------------------------------------------------+
    |
    |                     .-----------------.
    |       TLS           |                 |
    | (with mutual auth.) | Relying Party   |
    +-------------------->|                 |
             (6)          '-----------------'
~~~
{: #fig-arch title="Example Data Flow demonstrating Attested CSR with Background Check Model."}




# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Certificate Extensions {#cert-extension}

This section specifies the syntax and semantics of the Attestation Result Claims certificate extension, which provides a list of claims associated with the certificate subject appraised by the CA.

The Attestation Result Claims certificate extension MAY be included in public key certificates {{RFC5280}}. The Attestation Result Claims certificate extension MUST be identified by the following object identifier:

~~~ asn.1
id-pe-ar-claims OBJECT IDENTIFIER ::= {
    iso(1) identified-organization(3) dod(6) internet(1)
    security(5) mechanisms(5) pkix(7) id-pe(1) 34
}
~~~

This extension MUST NOT be marked critical.

The Attestation Result Claims extension MUST have the following syntax:

~~~ asn.1
AR-Claims ::= SET SIZE (1..MAX) OF AR-CLAIM
~~~

The `AR-Claims` represents attestation result claims included by the CA. It MUST contain at least one claim. For privacy reasons, the CA MAY include only a subset of the `AR-Claims` that were presented to it in an Attestation Result obtained from a Verifier. The CA may include in their certificate profile a list of verified evidence claims (identified by OID) that MAY be copied from the CSR to the certificate, while any other claims MUST NOT be copied. By removing the signature from the evidence, the CA is asserting that it has verified the Evidence to chain to a root that the CA trusts, but it is not required to disclose in the final certificate what that root is.

See {{sec-priv-cons}} for a discussion of privacy concerns related to re-publishing Evidence into a certificate.

## ASN.1 Module {#extclaims-asn}

This section provides an ASN.1 Module for the Evidence Claims certificate extension, and it follows the conventions established in {{RFC5912}} and {{RFC6268}}.

~~~ asn.1
EvidenceClaimsCertExtn
    { iso(1) identified-organization(3) dod(6) internet(1)
      security(5) mechanisms(5) pkix(7) id-mod(0)
      id-mod-evidenceclaims(TBD) }

DEFINITIONS IMPLICIT TAGS ::= BEGIN

IMPORTS 
    EXTENSION
    FROM PKIX-CommonTypes-2009 -- RFC 5912
        { iso(1) identified-organization(3) dod(6) internet(1)
          security(5) mechanisms(5) pkix(7) id-mod(0)
          id-mod-pkixCommon-02(57) };

END
~~~

-- Evidence Claims Certificate Extension

~~~ asn.1
ext-EvidenceClaims EXTENSION ::= {
    SYNTAX EvidenceClaims
    IDENTIFIED BY id-pe-evidenceclaims
}
~~~

-- EvidenceClaims Certificate Extension OID

~~~ asn.1
id-pe-evidenceclaims OBJECT IDENTIFIER ::= {
    iso(1) identified-organization(3) dod(6) internet(1)
    security(5) mechanisms(5) pkix(7) id-pe(1) 34
}
~~~

-- Evidence Claims Certificate Extension Syntax

~~~ asn.1
EvidenceClaims ::= SET SIZE (1..MAX) OF EVIDENCE-CLAIM
~~~


# Security Considerations {#sec-priv-cons}

The extension MUST NOT publish in the certificate any privacy-sensitive information that could compromise the end device. What counts as privacy-sensitive will vary by use case. For example:

1. **HSM Usage**: For a hardware security module (HSM) backing a public code-signing service, the model and firmware patch level could be considered sensitive as it could give an attacker an advantage in exploiting known vulnerabilities.

2. **Mobile Devices**: For a certificate issued to an end-user mobile computing device, any unique identifier could be used for tracking.

3. **IoT Devices**: For small IoT devices, knowing hardware and firmware version information could help edge gateways deny access to devices with known vulnerabilities.

The CA MUST have a configurable mechanism to control which information is copied from the provided Evidence into the certificate, for example, via a certificate profile or Certificate Practice Statement (CPS). CA operators should err on the side of caution and exclude unnecessary claims.

# IANA Considerations

For the `EvidenceClaims` certificate extension in {{extclaims-extension}}, IANA is requested to assign an object identifier (OID) for the certificate extension. The OID for the certificate extension should be allocated in the "SMI Security for PKIX Certificate Extension" registry (1.3.6.1.5.5.7.1).

For the ASN.1 Module in {{extclaims-asn}}, IANA is requested to assign an object identifier (OID) for the module identifier. The OID for the module should be allocated in the "SMI Security for PKIX Module Identifier" registry (1.3.6.1.5.5.7.0).


--- back

# Acknowledgments
{:numbered="false"}

The authors would like to thank ...

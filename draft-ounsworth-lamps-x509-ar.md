---
title: X.509 Certificate Extensions for Attestation Results
abbrev: X.509 Cert Extensions for ARs
docname: draft-ounsworth-lamps-x509-ar-latest
category: std
consensus: true
submissiontype: IETF

ipr: trust200902
area: Security
workgroup: LAMPS
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
    country: USA
    email: montywiseman32@gmail.com
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
    ins: N. Smith
    name: Ned Smith
    org: Intel Corporation
    country: USA
    email: ned.smith@intel.com

normative:
  RFC2119:
  RFC5280:
  RFC9334:
  I-D.ietf-rats-eat:
  I-D.ietf-rats-pkix-key-attestation:

informative:
  RFC5912:
  RFC9344:
  RFC6268:

--- abstract

This document defines extensions for X.509 certificates to include attestation results as part of the certificate's content. The primary use case for these extensions is in the context of Certificate Signing Request (CSR) attestation, where claims about the trustworthiness of an Attester are conveyed to the Certification Authority (CA) as part of the CSR process. These extensions enable the CA to appraise the submitted evidence and embed attestation results into the issued certificate. This allows Relying Parties to evaluate the Attester's trustworthiness consistently and efficiently, supporting scalable policies for verification in environments with diverse attestation technologies.

--- middle

# Introduction

Attestation mechanisms are increasingly used to verify the trustworthiness of devices and cryptographic keys. These mechanisms provide evidence that a device or key meets specific security criteria before being relied upon by an application. However, relying parties need a standardized way to access and validate these attestation results.

This document introduces the Attestation Results Certificate Extension, which enables Certification Authorities (CAs) to embed attestation results into issued X.509 certificates. By incorporating attestation results directly into certificates, Relying Parties can assess trustworthiness without requiring additional protocol interactions with external verifiers.

This extension is particularly useful in environments where:

* Devices generate key pairs and request certificates while providing evidence of their security characteristics, such as key storage protection and tamper resistance.

* Certification Authorities evaluate and verify attestation claims before issuing a certificate.

* Relying Parties benefit from a standardized way to evaluate CA-appraised key and platform security properties conveyed at the time of certificate issuance, especially for properties that change infrequently or are valid within the expected certificate lifetime and may optionally use real-time attestation to detect changes in the attester's security posture over time.

While PKIX Key Attestation {{I-D.ietf-rats-pkix-key-attestation}} defines a mechanism for carrying attestation evidence within a CSR, this document extends that concept to X.509 certificates by defining a Attestation Results Certificate Extension. This extension allows attestation results to be embedded directly into an issued certificate, enabling Relying Parties to verify the security characteristics of a key or its platform without requiring access to the original CSR or real-time attestation. Additionally, this document defines the ASN.1 syntax for the Attestation Results Certificate Extension and specifies how it should be included in X.509 certificates.

~~~ aasvg
                          .-----------------.
         Evidence (1)     |                 | Compare Evidence
   +--------------------->|     Verifier    | against Appraisal
   | Attestation Result(2)|                 | Policy
   |       +--------------'------------+----'
   |       |               
   |       |          
   |       |          
   |       v          
.------------.             .-----------------.                .-----.
|            +------------>|                 |--------------->|     |
| HSM        | Attestation | Registration    |                | CA  |
| (Attester) | Result      | Authority       |                |     |
|            | in CSR (3)  | (Relying Party) |                |     |
'------------'             '-----------------'                '-----'
    ^     ^                                                     |
    |     |    X.509 Certificate with Attestation Result (4)    |
    |     +-----------------------------------------------------+
    |
    |                     .-----------------.
    |       TLS           |                 |
    | (with mutual auth.) | Relying Party   |
    +-------------------->|                 |
             (5)          '-----------------'
~~~
{: #fig-arch title="Example Data Flow demonstrating Attested CSR with Passport Model."}

Steps 1 to 3, including the generation of an Attestation Result, its inclusion in a CSR, and its verification by a Registration Authority are already specified in {{I-D.ietf-rats-pkix-key-attestation}}. 

  * Step 5: The CA issues an X.509 certificate embedding the Attestation Results within the Attestation Results Certificate Extension.
  * Step 6: The Relying Party uses TLS with mutual authentication to verify the certificate and its Attestation Results, authenticating the Attester.

The intent of embedding attestation results in certificates is not to replace real-time attestation or duplicate the CA's device attestation validation, but to provide additional context about the attester's state at the time of certificate issuance in a standardized and machine-readable format that relying parties can consume. This enables relying parties to make informed decisions during certificate validation. For example, the embedded attestation information can be cross-checked against real-time attestation results to detect potential deviations in the attester's current security posture. Mechanisms such as those described in {{?I-D.fossati-tls-exported-attestation}} allow attesters to convey real-time evidence securely and bind it to the TLS session.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Certificate Extensions {#cert-extension}

This section specifies the syntax and semantics of the Attestation Results certificate extension, which provides attestation results associated with the certificate subject appraised by the CA.

The Attestation Results certificate extension MAY be included in public key certificates {{RFC5280}}. The Attestation Results certificate extension MUST be identified by the following object identifier:

~~~ asn.1
id-pe-ar-claims OBJECT IDENTIFIER ::= {
    iso(1) identified-organization(3) dod(6) internet(1)
    security(5) mechanisms(5) pkix(7) id-pe(1) 34
}
~~~

This extension MUST NOT be marked critical.

The Attestation Results extension MUST have the following syntax:

~~~ asn.1
AR-Claims ::= SEQUENCE SIZE (1..MAX) OF ReportedEntity
~~~

The AR-Claims field represents a sequence of Attestation Results claims (ReportedEntity) added by the CA in the certificate. It MUST contain at least one claim. For privacy reasons, the CA MAY choose to include only a subset of the claims from the Attestation Result it received from a Verifier. The CA's certificate profile can specify which Attestation Result claims (identified by OIDs) MAY be copied from the Attestation Evidence provided in the CSR; any others MUST NOT be copied.

See {{sec-priv-cons}} for a discussion of privacy concerns related to re-publishing Evidence into a certificate.

The platform entity and key entity are relevant to the Attestation Results Certificate Extension in the context of attesting to the security properties of a key or the platform that manages it.

## id-pkix-attest-entity-platform (Platform Attestation)

- This attests that the platform hosting the key meets security requirements.
- Useful when the integrity of the system running cryptographic operations is important.
- Example: A certificate extension proving the FIPS level at which the attestor is currently operating in compliance with.

## id-pkix-attest-entity-key (Key Attestation)

- This attests to the security properties of a specific cryptographic key, regardless of the platform.
- Ensures that the key is stored securely and follows cryptographic policies.
- Example: A certificate extension proving that the private key of the certificate is hardware-protected and cannot be exported to a software cryptographic module.

## ASN.1 Module {#extclaims-asn}

This section provides an ASN.1 Module for the Attestation Results certificate extension, and it follows the conventions established in {{RFC5912}} and {{RFC6268}}.

~~~ asn.1
AttestationResultsCertExtn
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

-- Evidence Claims Certificate Extension OID
id-pe-attestationResults OBJECT IDENTIFIER ::= {
    iso(1) identified-organization(3) dod(6) internet(1)
    security(5) mechanisms(5) pkix(7) id-pe(1) 34
}

-- Evidence Claims Certificate Extension
ext-AttestationResults EXTENSION ::= {
    SYNTAX AttestationResults
    IDENTIFIED BY id-pe-attestationResults
}

-- Evidence Claims Syntax
AttestationResults ::= SEQUENCE SIZE (1..MAX) OF ReportedEntity

-- Alignment with PkixAttestation structure
ReportedEntity ::= SEQUENCE {
    entityType         OBJECT IDENTIFIER,
    reportedAttributes SEQUENCE SIZE (1..MAX) OF ReportedAttribute
}

ReportedAttribute ::= SEQUENCE {
    attributeType      OBJECT IDENTIFIER,
    value              AttributeValue
}

AttributeValue ::= CHOICE {
    bytes       [0] IMPLICIT OCTET STRING,
    utf8String  [1] IMPLICIT UTF8String,
    bool        [2] IMPLICIT BOOLEAN,
    time        [3] IMPLICIT GeneralizedTime,
    int         [4] IMPLICIT INTEGER,
    oid         [5] IMPLICIT OBJECT IDENTIFIER
}
~~~

# Security Considerations {#sec-priv-cons}

The extension MUST NOT publish in the certificate any privacy-sensitive information that could compromise the end device. What counts as privacy-sensitive will vary by use case. For example:

1. HSM Usage: For a hardware security module (HSM) backing a public code-signing service, the model and firmware patch level could be considered sensitive as it could give an attacker an advantage in exploiting known vulnerabilities.

2. Mobile Devices: For a certificate issued to an end-user mobile computing device, any unique identifier could be used for tracking.

3. IoT Devices: For small IoT devices, knowing hardware and firmware version information could help edge gateways deny access to devices with known vulnerabilities.

The CA MUST have a configurable mechanism to control which information is copied from the provided Attestation Results into the certificate, for example, via a certificate profile or Certificate Practice Statement (CPS). CA operators should err on the side of caution and exclude unnecessary claims. Avoiding unnecessary claims also mitigates the risk of targeted attacks, where an attacker could exploit knowledge
of hardware versions, models, etc.

# IANA Considerations

For the AttestationResults certificate extension in {{extclaims-asn}}, IANA is requested to assign an object identifier (OID) for the certificate extension. The OID for the certificate extension should be allocated in the "SMI Security for PKIX Certificate Extension" registry (1.3.6.1.5.5.7.1).

For the ASN.1 Module in {{extclaims-asn}}, IANA is requested to assign an object identifier (OID) for the module identifier. The OID for the module should be allocated in the "SMI Security for PKIX Module Identifier" registry (1.3.6.1.5.5.7.0).

--- back

# Acknowledgments
{:numbered="false"}

The authors would like to thank ...

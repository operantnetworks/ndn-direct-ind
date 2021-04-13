/**
 * Copyright (C) 2021 Operant Networks, Incorporated.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version, with the additional exemption that
 * compiling, linking, and/or using OpenSSL is allowed.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU Lesser General Public License is in the file COPYING.
 */

var Blob = require('../../util/blob.js').Blob; /** @ignore */
var SignedBlob = require('../../util/signed-blob.js').SignedBlob; /** @ignore */
var Name = require('../../name.js').Name; /** @ignore */
var DerNode = require('../../encoding/der/der-node.js').DerNode;
var OID = require('../../encoding/oid.js').OID; /** @ignore */
var ValidityPeriod = require('../../security/validity-period.js').ValidityPeriod;

/**
 * An X509CertificateInfo holds the fields from decoding an X.509 certificate.
 *
 * There are two forms of the constructor:
 * X509CertificateInfo(encoding) - Create an X509CertificateInfo by decoding an
 * X.509 certificate.
 * X509CertificateInfo(issuerName, alidityPeriod, subjectName, publicKey, signatureValue) -
 * Create an X509CertificateInfo from the given values. This sets the serial
 * number to 0. You can use getEncoding() to get the X.509 certificate.
 * @param {Blob} encoding The encoded X.509 certificate.
 * @param {Name} issuerName The issuer name, which is converted according to
 * makeX509Name(). If the name doesn't start with /x509, then it should
 * follow conventions for an NDN key name. This copies the name.
 * @param {ValidityPeriod} validityPeriod The validity period. This copies the object.
 * @param {Name} subjectName The subject name, which is converted according to
 * makeX509Name(). If the name doesn't start with /x509, then it should
 * follow conventions for an NDN certificate name. This copies the name.
 * @param {Blob} publicKey The bytes of the public key DER.
 * @param {Blob} signatureValue The bytes of the signature value. This assumes the
 * algorithm is RSA with SHA-256.
 * @throws Error for error decoding the certificate.
 * @constructor
 */
var X509CertificateInfo = function X509CertificateInfo
  (issuerName, validityPeriod, subjectName, publicKey, signatureValue)
{
  if (issuerName instanceof Blob) {
    encoding = issuerName;

    // See https://tools.ietf.org/html/rfc5280 .
    // Certificate  ::=  SEQUENCE  {
    //      tbsCertificate       TBSCertificate,
    //      signatureAlgorithm   AlgorithmIdentifier,
    //      signatureValue       BIT STRING  }
    var tbsCertificate;
    var signatureAlgorithm;
    try {
      this.root_ = DerNode.parse(encoding);
      var rootChildren = this.root_.getChildren();
      if (rootChildren.length < 3)
        throw new Error("X509CertificateInfo: Expected 3 certificate fields");
      tbsCertificate = DerNode.getSequence(rootChildren, 0);
      signatureAlgorithm = DerNode.getSequence(rootChildren, 1);
      var signatureValueNode = rootChildren[2];

      // Expect the first byte of the BIT STRING to be zero.
      if (!(signatureValueNode instanceof DerNode.DerBitString) ||
          signatureValueNode.getPayload().size() < 1 ||
          signatureValueNode.getPayload().buf()[0] != 0)
        throw new Error("X509CertificateInfo: Cannot decode signatureValue");
      this.signatureValue_ = new Blob
        (signatureValueNode.getPayload().buf().slice(1, signatureValueNode.getPayload().size()));

      // Get the signed portion.
      var beginOffset = this.root_.getHeaderSize();
      var endOffset = beginOffset + tbsCertificate.getSize();
      this.signedEncoding_ = new SignedBlob(encoding, beginOffset, endOffset);
    } catch (ex) {
      throw new Error("X509CertificateInfo: Cannot decode certificate: " + ex);
    }

    //TBSCertificate  ::=  SEQUENCE  {
    //      version         [0]  EXPLICIT Version DEFAULT v1,
    //      serialNumber         CertificateSerialNumber,
    //      signature            AlgorithmIdentifier,
    //      issuer               Name,
    //      validity             Validity,
    //      subject              Name,
    //      subjectPublicKeyInfo SubjectPublicKeyInfo,
    //      issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
    //                           -- If present, version MUST be v2 or v3
    //      subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
    //                           -- If present, version MUST be v2 or v3
    //      extensions      [3]  EXPLICIT Extensions OPTIONAL
    //                           -- If present, version MUST be v3
    //      }
    try {
      var tbsChildren = tbsCertificate.getChildren();

      var versionOffset = 0;
      if (tbsChildren.length >= 1 && tbsChildren[0] instanceof DerNode.DerExplicit)
        // There is a version.
        versionOffset = 1;
      if (tbsChildren.length < 6 + versionOffset)
        throw new Error("X509CertificateInfo: Expected 6 TBSCertificate fields");

      this.issuerName_ = X509CertificateInfo.makeName(tbsChildren[2 + versionOffset], null);

      // validity
      var validityChildren = DerNode.getSequence
        (tbsChildren, 3 + versionOffset).getChildren();
      var notBefore = validityChildren[0];
      var notAfter = validityChildren[1];
      if (!(notBefore instanceof DerNode.DerUtcTime) ||
          !(notAfter instanceof DerNode.DerUtcTime))
        throw new Error("X509CertificateInfo: Cannot decode Validity");
      this.validityPeriod_ = new ValidityPeriod(notBefore.toVal(), notAfter.toVal());

      // Get the extensions.
      var extensions = null;
      var extensionsExplicit = tbsChildren[tbsChildren.length - 1];
      if (extensionsExplicit instanceof DerNode.DerExplicit &&
          extensionsExplicit.getTag() == 3 &&
          extensionsExplicit.getChildren().length == 1)
        extensions = extensionsExplicit.getChildren()[0];

      this.subjectName_ = X509CertificateInfo.makeName
        (tbsChildren[4 + versionOffset], extensions);

      this.publicKey_ = tbsChildren[5 + versionOffset].encode();
    } catch (ex) {
      throw new Error("X509CertificateInfo: Cannot decode the TBSCertificate: " + ex);
    }
  }
  else {
    this.issuerName_ = new Name(issuerName);
    this.validityPeriod_ = new ValidityPeriod(validityPeriod);
    this.subjectName_ = new Name(subjectName);
    this.publicKey_ = publicKey;
    this.signatureValue_ = signatureValue;

    // We are using certificate extensions, so we must set the version.
    var version = new DerNode.DerExplicit(0);
    version.addChild(new DerNode.DerInteger(2));

    var algorithmIdentifier =new DerNode.DerSequence();
    algorithmIdentifier.addChild(new DerNode.DerOid
      (X509CertificateInfo.RSA_ENCRYPTION_OID));
    algorithmIdentifier.addChild(new DerNode.DerNull());

    var tbsCertificate = new DerNode.DerSequence();
    //TBSCertificate  ::=  SEQUENCE  {
    //      version         [0]  EXPLICIT Version DEFAULT v1,
    //      serialNumber         CertificateSerialNumber,
    //      signature            AlgorithmIdentifier,
    //      issuer               Name,
    //      validity             Validity,
    //      subject              Name,
    //      subjectPublicKeyInfo SubjectPublicKeyInfo
    //      }
    tbsCertificate.addChild(version);
    tbsCertificate.addChild(new DerNode.DerInteger(0));
    tbsCertificate.addChild(algorithmIdentifier);
    tbsCertificate.addChild(X509CertificateInfo.makeX509Name(issuerName, null));

    var validity = new DerNode.DerSequence();
    validity.addChild(new DerNode.DerUtcTime(validityPeriod.getNotBefore()));
    validity.addChild(new DerNode.DerUtcTime(validityPeriod.getNotAfter()));
    tbsCertificate.addChild(validity);

    var extensions = new DerNode.DerSequence();
    tbsCertificate.addChild(X509CertificateInfo.makeX509Name(subjectName, extensions));

    try {
      tbsCertificate.addChild(DerNode.parse(publicKey));
    } catch (ex) {
      throw new Error("X509CertificateInfo: publicKey encoding is invalid DER: " + ex);
    }

    if (extensions.getChildren().length > 0) {
      // makeX509Name added to extensions, so include it.
      var extensionsExplicit = new DerNode.DerExplicit(3);
      extensionsExplicit.addChild(extensions);
      tbsCertificate.addChild(extensionsExplicit);
    }

    // Certificate  ::=  SEQUENCE  {
    //      tbsCertificate       TBSCertificate,
    //      signatureAlgorithm   AlgorithmIdentifier,
    //      signatureValue       BIT STRING  }
    this.root_ = new DerNode.DerSequence();
    this.root_.addChild(tbsCertificate);
    this.root_.addChild(algorithmIdentifier);
    this.root_.addChild(new DerNode.DerBitString(signatureValue.buf(), 0));

    // Get the signed portion.
    var beginOffset = this.root_.getHeaderSize();
    var endOffset = beginOffset + tbsCertificate.getSize();
    this.signedEncoding_ = new SignedBlob(this.root_.encode(), beginOffset, endOffset);
  }
};

exports.X509CertificateInfo = X509CertificateInfo;

/**
 * Get the SignedBlob of the encoding with the offsets for the signed portion.
 * @return {SignedBlob} The SignedBlob of the encoding.
 */
X509CertificateInfo.prototype.getEncoding = function()
{
  return this.signedEncoding_;
};

/**
 * Get the issuer name which has been converted to an NDN name.
 * @return {Name} The issuer name.
 */
X509CertificateInfo.prototype.getIssuerName = function()
{
  return this.issuerName_;
};

/**
 * Get the validity period
 * @return {ValidityPeriod} The validity period.
 */
X509CertificateInfo.prototype.getValidityPeriod = function()
{
  return this.validityPeriod_;
};

/**
 * Get the subject name which has been converted to an NDN name.
 * @return {Name} The subject name.
 */
X509CertificateInfo.prototype.getSubjectName = function()
{
  return this.subjectName_;
};

/**
 * Get the public key DER encoding.
 * @return {Blob} The DER encoding Blob.
 */
X509CertificateInfo.prototype.getPublicKey = function()
{
  return this.publicKey_;
};

/**
 * Get the signature value bytes.
 * @return {Blob} The signature value.
 */
X509CertificateInfo.prototype.getSignatureValue = function()
{
  return this.signatureValue_;
};

/**
 * Check if the Name has two components and the first component is "x509". The
 * second component should be the encoding of the X.509 name.
 * @param {Name} name The Name to check.
 * @return {boolean} True if name is an encapsulated X.509 name.
 */
X509CertificateInfo.isEncapsulatedX509 = function(name)
{
  return name.size() === 2 && name.get(0).equals(X509CertificateInfo.X509_COMPONENT);
};

/**
 * Make an NDN Name from the URI field in the Subject Alternative Names
 * extension, if available. Otherwise make an NDN name that encapsulates the
 * X.509 name, where the first component is "x509" and the second is the
 * encoded X.509 name. This should be the reverse operation of makeX509Name().
 * @param {DerNode} x509Name The DerNode of the X.509 name, used if extensions
 * is null or doesn't have a URI field in the Subject Alternative Names.
 * @param {DerNode} extensions The DerNode of the extensions (the only child of
 * the DerExplicit node with tag 3). If this is null, don't use it.
 * @return {Name} The NDN Name.
 */
X509CertificateInfo.makeName = function(x509Name, extensions)
{
  if (extensions != null) {
    // Try to get the URI field in the Subject Alternative Names.

    //Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
    //
    // Extension  ::=  SEQUENCE  {
    //    extnID      OBJECT IDENTIFIER,
    //    critical    BOOLEAN DEFAULT FALSE,
    //    extnValue   OCTET STRING
    //                -- contains the DER encoding of an ASN.1 value
    //                -- corresponding to the extension type identified
    //                -- by extnID
    //    }
    //
    // subjectAltName EXTENSION ::= {
    // 	SYNTAX GeneralNames
    // 	IDENTIFIED BY id-ce-subjectAltName
    // }
    //
    // GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
    //
    // GeneralName ::= CHOICE {
    // 	otherName	[0] INSTANCE OF OTHER-NAME,
    // 	rfc822Name	[1] IA5String,
    // 	dNSName		[2] IA5String,
    // 	x400Address	[3] ORAddress,
    // 	directoryName	[4] Name,
    // 	ediPartyName	[5] EDIPartyName,
    // 	uniformResourceIdentifier [6] IA5String,
    // 	IPAddress	[7] OCTET STRING,
    // 	registeredID	[8] OBJECT IDENTIFIER
    var extensionsChildren = extensions.getChildren();

    for (var i = 0; i < extensionsChildren.length; ++i) {
      var extension = extensionsChildren[i];
      if (!(extension instanceof DerNode.DerSequence))
        // We don't expect this.
        continue;
      var extensionChildren = extension.getChildren();

      if (extensionChildren.length < 2 || extensionChildren.length > 3)
        // We don't expect this.
        continue;
      var oid = extensionChildren[0];
      // Ignore "critical".
      var extensionValue = extensionChildren[extensionChildren.length - 1];
      if (!(oid instanceof DerNode.DerOid) ||
          !(extensionValue instanceof DerNode.DerOctetString))
        // We don't expect this.
        continue;
      if (oid.toVal() != X509CertificateInfo.SUBJECT_ALTERNATIVE_NAME_OID)
        // Try the next extension.
        continue;

      try {
        var generalNames = DerNode.parse(extensionValue.toVal());
        var generalNamesChildren = generalNames.getChildren();
        for (var i = 0; i < generalNamesChildren.length; ++i) {
          var value = generalNamesChildren[i];
          if (!(value instanceof DerNode.DerImplicitByteString))
            // We don't expect this.
            continue;

          if (value.getType() == X509CertificateInfo.SUBJECT_ALTERNATIVE_NAME_URI_TYPE)
            // Return an NDN name made from the URI.
            return new Name(value.toVal().toString());
        }
      } catch (ex) {
        // We don't expect this.
        continue;
      }
    }
  }

  // Default behavior: Encapsulate the X.509 name.
  return new Name().append(X509CertificateInfo.X509_COMPONENT).append(x509Name.encode());
};

/**
 * If the Name has two components and the first is "x509" (see
 * isEncapsulatedX509), then return a DerNode made from the second component.
 * Otherwise, return a DerNode which is a short representation of the Name,
 * and update the extensions by adding a Subject Alternative Names extension
 * with a URI field for the NDN Name. This should be the reverse operation of
 * makeName().
 * @param {Name} name The NDN name.
 * @param {DerNode} extensions The DerNode of the extensions (the only child of
 * the DerExplicit node with tag 3). If the NDN Name is not an encapsulated
 * X.509 name, then add the Subject Alternative Names extensions (without first
 * checking if extensions already has one). If this is null, don't use it.
 * @return {DerNode} A DerNode of the X.509 name.
 */
X509CertificateInfo.makeX509Name = function(name, extensions)
{
  if (X509CertificateInfo.isEncapsulatedX509(name))
    // Just decode the second component.
    return DerNode.parse(name.get(1).getValue());

  var uri = name.toUri();
  if (extensions instanceof DerNode.DerSequence) {
    // Add the Subject Alternative Names without checking if one already exists.
    var generalNames = new DerNode.DerSequence();
    generalNames.addChild(new DerNode.DerImplicitByteString
      (new Blob(uri).buf(), X509CertificateInfo.SUBJECT_ALTERNATIVE_NAME_URI_TYPE));
    var generalNamesEncoding = generalNames.encode();

    var extension = new DerNode.DerSequence();
    extension.addChild(new DerNode.DerOid
      (new OID(X509CertificateInfo.SUBJECT_ALTERNATIVE_NAME_OID)));
    extension.addChild(new DerNode.DerOctetString(generalNamesEncoding.buf()));
    extensions.addChild(extension);
  }

  // Make an X.509 name with a "pseudonym.
  var root = new DerNode.DerSequence();
  var typeAndValue = new DerNode.DerSequence();
  typeAndValue.addChild(new DerNode.DerOid(new OID(X509CertificateInfo.PSEUDONYM_OID)));
  typeAndValue.addChild(new DerNode.DerUtf8String(new Blob(uri).buf()));
  var component = new DerNode.DerSet();
  component.addChild(typeAndValue);

  root.addChild(component);
  return root;
};

X509CertificateInfo.RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1";
X509CertificateInfo.PSEUDONYM_OID = "2.5.4.65";
X509CertificateInfo.SUBJECT_ALTERNATIVE_NAME_OID = "2.5.29.17";
X509CertificateInfo.SUBJECT_ALTERNATIVE_NAME_URI_TYPE = 0x86;
X509CertificateInfo.X509_COMPONENT = new Name.Component("x509");

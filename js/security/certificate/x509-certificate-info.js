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

      this.issuerName_ = X509CertificateInfo.makeName(tbsChildren[2 + versionOffset]);

      // validity
      var validityChildren = DerNode.getSequence
        (tbsChildren, 3 + versionOffset).getChildren();
      var notBefore = validityChildren[0];
      var notAfter = validityChildren[1];
      if (!(notBefore instanceof DerNode.DerUtcTime) ||
          !(notAfter instanceof DerNode.DerUtcTime))
        throw new Error("X509CertificateInfo: Cannot decode Validity");
      this.validityPeriod_ = new ValidityPeriod(notBefore.toVal(), notAfter.toVal());

      this.subjectName_ = X509CertificateInfo.makeName(tbsChildren[4 + versionOffset]);

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

    var algorithmIdentifier =new DerNode.DerSequence();
    algorithmIdentifier.addChild(new DerNode.DerOid
      (X509CertificateInfo.RSA_ENCRYPTION_OID));
    algorithmIdentifier.addChild(new DerNode.DerNull());

    var tbsCertificate = new DerNode.DerSequence();
    //TBSCertificate  ::=  SEQUENCE  {
    //      serialNumber         CertificateSerialNumber,
    //      signature            AlgorithmIdentifier,
    //      issuer               Name,
    //      validity             Validity,
    //      subject              Name,
    //      subjectPublicKeyInfo SubjectPublicKeyInfo
    //      }
    tbsCertificate.addChild(new DerNode.DerInteger(0));
    tbsCertificate.addChild(algorithmIdentifier);
    tbsCertificate.addChild(X509CertificateInfo.makeX509Name(issuerName));

    var validity = new DerNode.DerSequence();
    validity.addChild(new DerNode.DerUtcTime(validityPeriod.getNotBefore()));
    validity.addChild(new DerNode.DerUtcTime(validityPeriod.getNotAfter()));
    tbsCertificate.addChild(validity);

    tbsCertificate.addChild(X509CertificateInfo.makeX509Name(subjectName));

    try {
      tbsCertificate.addChild(DerNode.parse(publicKey));
    } catch (ex) {
      throw new Error("X509CertificateInfo: publicKey encoding is invalid DER: " + ex);
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
 * Convert an X.509 name to an NDN Name. This should be the reverse operation
 * of makeX509Name().
 * @param {DerNode} x509Name The DerNode of the X.509 name.
 * @return {Name} The NDN Name.
 */
X509CertificateInfo.makeName = function(x509Name)
{
  // Check if there is a UTF8 string with the OID for "pseudonym".
  var components = x509Name.getChildren();
  for (var i = 0; i < components.length; ++i) {
    var component = components[i];
    if (!(component instanceof DerNode.DerSet))
      // Not a valid X.509 name. Don't worry about it and continue below to use the encoding.
      break;
    var componentChildren = component.getChildren();
    if (componentChildren.length !== 1)
      break;
    var typeAndValue = componentChildren[0];
    if (!(typeAndValue instanceof DerNode.DerSequence))
      break;
    var typeAndValueChildren = typeAndValue.getChildren();
    if (typeAndValueChildren.length !== 2)
      break;

    var oid = typeAndValueChildren[0];
    var value = typeAndValueChildren[1];

    if ((oid instanceof DerNode.DerOid) && (value instanceof DerNode.DerUtf8String) &&
        oid.toVal() == X509CertificateInfo.PSEUDONYM_OID)
      return new Name(value.toVal().toString());
  }

  return new Name().append(X509CertificateInfo.X509_COMPONENT).append(x509Name.encode());
};

/**
 * If the Name has two components and the first is "x509", then return the
 * DerNode of the second component. Otherwise, return the DerNode of an
 * X.509 name with one component where the type is "pseudonym" and the value
 * is a UTF8 string with the name URI. This should be the reverse operation
 * of makeName().
 * @param {Name} name The NDN name.
 * @return {DerNode} A DerNode of the X.509 name.
 */
X509CertificateInfo.makeX509Name = function(name)
{
  if (X509CertificateInfo.isEncapsulatedX509(name))
    // Just decode the second component.
    return DerNode.parse(name.get(1).getValue());

  // Make an X.509 name with a "pseudonym.
  var root = new DerNode.DerSequence();
  var typeAndValue = new DerNode.DerSequence();
  typeAndValue.addChild(new DerNode.DerOid(new OID(X509CertificateInfo.PSEUDONYM_OID)));
  var uri = name.toUri();
  typeAndValue.addChild(new DerNode.DerUtf8String(new Blob(uri).buf()));
  var component = new DerNode.DerSet();
  component.addChild(typeAndValue);

  root.addChild(component);
  return root;
};

X509CertificateInfo.RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1";
X509CertificateInfo.PSEUDONYM_OID = "2.5.4.65";
X509CertificateInfo.X509_COMPONENT = new Name.Component("x509");

/**
 * Copyright (C) 2021 Operant Networks, Incorporated.
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: js/security/v2/certificate-v2.js
 * Original repository: https://github.com/named-data/ndn-js
 *
 * Summary of Changes: Add getSignedEncoding and getSignatureValue.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2017-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/v2/certificate.hpp
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
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

/** @ignore */
var Crypto = require('../../crypto.js'); /** @ignore */
var Name = require('../../name.js').Name; /** @ignore */
var Data = require('../../data.js').Data; /** @ignore */
var KeyLocator = require('../../key-locator.js').KeyLocator; /** @ignore */
var KeyLocatorType = require('../../key-locator.js').KeyLocatorType; /** @ignore */
var Sha256WithRsaSignature = require('../../sha256-with-rsa-signature.js').Sha256WithRsaSignature; /** @ignore */
var Sha256WithEcdsaSignature = require('../../sha256-with-ecdsa-signature.js').Sha256WithEcdsaSignature; /** @ignore */
var DigestSha256Signature = require('../../digest-sha256-signature.js').DigestSha256Signature; /** @ignore */
var X509CertificateInfo = require('../../security/certificate/x509-certificate-info').X509CertificateInfo; /** @ignore */
var DerNodeType = require('../../encoding/der/der-node-type.js').DerNodeType; /** @ignore */
var Blob = require('../../util/blob.js').Blob; /** @ignore */
var ContentType = require('../../meta-info.js').ContentType; /** @ignore */
var WireFormat = require('../../encoding/wire-format.js').WireFormat; /** @ignore */
var SignedBlob = require('../../util/signed-blob.js').SignedBlob; /** @ignore */
var ValidityPeriod = require('../validity-period.js').ValidityPeriod; /** @ignore */
var InvalidArgumentException = require('../security-exception.js').InvalidArgumentException;

/**
 * CertificateV2 represents a certificate following the certificate format
 * naming convention.
 *
 * Overview of the NDN certificate format:
 *
 *     CertificateV2 ::= DATA-TLV TLV-LENGTH
 *                         Name      (= /<NameSpace>/KEY/[KeyId]/[IssuerId]/[Version])
 *                         MetaInfo  (.ContentType = KEY)
 *                         Content   (= X509PublicKeyContent)
 *                         SignatureInfo (= CertificateV2SignatureInfo)
 *                         SignatureValue
 *
 *     X509PublicKeyContent ::= CONTENT-TLV TLV-LENGTH
 *                                BYTE+ (= public key bits in PKCS#8 format)
 *
 *     CertificateV2SignatureInfo ::= SIGNATURE-INFO-TYPE TLV-LENGTH
 *                                      SignatureType
 *                                      KeyLocator
 *                                      ValidityPeriod
 *                                      ... optional critical or non-critical extension blocks ...
 *
 * An example of NDN certificate name:
 *
 *     /edu/ucla/cs/yingdi/KEY/%03%CD...%F1/%9F%D3...%B7/%FD%d2...%8E
 *     \_________________/    \___________/ \___________/\___________/
 *    Certificate Namespace      Key Id       Issuer Id     Version
 *         (Identity)
 *     \__________________________________/
 *                   Key Name
 *
 * Notes:
 *
 * - `Key Id` is an opaque name component to identify the instance of the public
 *   key for the certificate namespace. The value of `Key ID` is controlled by
 *   the namespace owner. The library includes helpers for generating key IDs
 *   using an 8-byte random number, SHA-256 digest of the public key, timestamp,
 *   and the specified numerical identifiers.
 *
 * - `Issuer Id` is sn opaque name component to identify the issuer of the
 *   certificate. The value is controlled by the issuer. The library includes
 *   helpers to set issuer the ID to an 8-byte random number, SHA-256 digest of
 *   the issuer's public key, and the specified numerical identifiers.
 *
 * - `Key Name` is a logical name of the key used for management purposes. the
 *    Key Name includes the certificate namespace, keyword `KEY`, and `KeyId`
 *    components.
 *
 * @see https://github.com/named-data/ndn-cxx/blob/master/docs/specs/certificate-format.rst
 *
 * Create a CertificateV2 from the content in the Data packet (if not omitted).
 * @param {Data} data (optional) The data packet with the content to copy.
 * If omitted, create a CertificateV2 with content type KEY and default or
 * unspecified values.
 * @constructor
 */
var CertificateV2 = function CertificateV2(data)
{
  this.x509Info_ = null;

  // Call the base constructor.
  if (data != undefined) {
    Data.call(this, data);
    if (data instanceof X509CertificateInfo)
      this.x509Info_ = data.x509Info_;
    this.checkFormat_();
  }
  else {
    Data.call(this);
    this.getMetaInfo().setType(ContentType.KEY);
  }
};

CertificateV2.prototype = new Data();
CertificateV2.prototype.name = "CertificateV2";

exports.CertificateV2 = CertificateV2;

/**
 * Create a new CertificateV2.Error to report an error for not complying with
 * the certificate format.
 * Call with: throw new CertificateV2.Error(new Error("message")).
 * @constructor
 * @param {Error} error The exception created with new Error.
 */
CertificateV2.Error = function CertificateV2Error(error)
{
  if (error) {
    error.__proto__ = CertificateV2.Error.prototype;
    return error;
  }
};

CertificateV2.Error.prototype = new Error();
CertificateV2.Error.prototype.name = "CertificateV2Error";

CertificateV2.prototype.checkFormat_ = function()
{
  if (!CertificateV2.isValidName(this.getName()))
    throw new CertificateV2.Error(new Error
      ("The Data Name does not follow the certificate naming convention"));

  if (this.getMetaInfo().getType() != ContentType.KEY)
    throw new CertificateV2.Error(new Error("The Data ContentType is not KEY"));

  if (this.getMetaInfo().getFreshnessPeriod() < 0.0)
    throw new CertificateV2.Error(new Error
      ("The Data FreshnessPeriod is not set"));

  if (this.x509Info_ == null && this.getContent().size() == 0)
    throw new CertificateV2.Error(new Error("The Data Content is empty"));
};

/**
 * Get key name from the certificate name.
 * @return {Name} The key name as a new Name.
 */
CertificateV2.prototype.getKeyName = function()
{
  if (this.getName().size() < CertificateV2.MIN_CERT_NAME_LENGTH)
    throw new CertificateV2.Error(new Error
      ("The certificate has an encapsulated X.509 name, not an NDN cert name"));
  return this.getName().getPrefix(CertificateV2.KEY_ID_OFFSET + 1);
};

/**
 * Get the identity name from the certificate name.
 * @return {Name} The identity name as a new Name.
 */
CertificateV2.prototype.getIdentity = function()
{
  if (this.getName().size() < CertificateV2.MIN_CERT_NAME_LENGTH)
    throw new CertificateV2.Error(new Error
      ("The certificate has an encapsulated X.509 name, not an NDN cert name"));
  return this.getName().getPrefix(CertificateV2.KEY_COMPONENT_OFFSET);
};

/**
 * Get the key ID component from the certificate name.
 * @return {Name.Component} The key ID name component.
 */
CertificateV2.prototype.getKeyId = function()
{
  if (this.getName().size() < CertificateV2.MIN_CERT_NAME_LENGTH)
    throw new CertificateV2.Error(new Error
      ("The certificate has an encapsulated X.509 name, not an NDN cert name"));
  return this.getName().get(CertificateV2.KEY_ID_OFFSET);
};

/**
 * Get the issuer ID component from the certificate name.
 * @return {Name.Component} The issuer ID component.
 */
CertificateV2.prototype.getIssuerId = function()
{
  if (this.getName().size() < CertificateV2.MIN_CERT_NAME_LENGTH)
    throw new CertificateV2.Error(new Error
      ("The certificate has an encapsulated X.509 name, not an NDN cert name"));
  return this.getName().get(CertificateV2.ISSUER_ID_OFFSET);
};

/**
 * Get the public key DER encoding.
 * @return {Blob} The DER encoding Blob.
 * @throws CertificateV2.Error If the public key is not set.
 */
CertificateV2.prototype.getPublicKey = function()
{
  if (this.x509Info_ != null)
    return this.x509Info_.getPublicKey();

  if (this.getContent().size() == 0)
    throw new CertificateV2.Error(new Error
      ("The public key is not set (the Data content is empty)"));

  return this.getContent();
};

/**
 * Get the certificate validity period from the SignatureInfo.
 * @return {ValidityPeriod} The ValidityPeriod object.
 * @throws InvalidArgumentException If the SignatureInfo doesn't have a
 * ValidityPeriod.
 */
CertificateV2.prototype.getValidityPeriod = function()
{
  if (this.x509Info_ != null)
    return this.x509Info_.getValidityPeriod();

  if (!ValidityPeriod.canGetFromSignature(this.getSignature()))
    throw new InvalidArgumentException(new Error
      ("The SignatureInfo does not have a ValidityPeriod"));

  return ValidityPeriod.getFromSignature(this.getSignature());
};

/**
 * Check if the time falls within the validity period.
 * @param {number} time (optional) The time to check as milliseconds since
 * Jan 1, 1970 UTC. If omitted, use the current time.
 * @return {boolean} True if the beginning of the validity period is less than
 * or equal to time and time is less than or equal to the end of the validity
 * period.
 * @throws InvalidArgumentException If the SignatureInfo doesn't have a
 * ValidityPeriod.
 */
CertificateV2.prototype.isValid = function(time)
{
  return this.getValidityPeriod().isValid(time);
};

/**
 * Check if this certificate has an issuer name in the signature's key locator.
 * @return {boolean} True if this has an issue name.
 */
CertificateV2.prototype.hasIssuerName = function()
{
  if (this.x509Info_ != null)
    return true;

  return KeyLocator.canGetFromSignature(this.getSignature()) &&
    KeyLocator.getFromSignature(this.getSignature()).getType() === KeyLocatorType.KEYNAME;
};

/**
 * Get the issuer name from the signature's key locator. You should first call
 * hasIssuerName() to check if it exists.
 * @return {Name} The issuer name.
 */
CertificateV2.prototype.getIssuerName = function()
{
  if (this.x509Info_ != null)
    return this.x509Info_.getIssuerName();

  return KeyLocator.getFromSignature(this.getSignature()).getKeyName();
};

/**
 * Get the SignedBlob of the encoding with the offsets for the signed portion.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the Data packet. If omitted, use WireFormat getDefaultWireFormat().
 * @return {SignedBlob} The SignedBlob of the encoding, or an isNull() Blob if
 * can't encode.
 */
CertificateV2.prototype.getSignedEncoding = function(wireFormat)
{
  if (this.x509Info_ != null)
    return this.x509Info_.getEncoding();

  var signedEncoding = new SignedBlob();
  try {
    // This will use a cached encoding if available.
    signedEncoding = this.wireEncode(wireFormat);
  } catch (err) {
    // The signedEncoding isNull().
  }

  return signedEncoding;
};

/**
 * Get the signature value.
 * @return {Blob} A Blob with the bytes of the signature value..
 */
CertificateV2.prototype.getSignatureValue = function()
{
  if (this.x509Info_ != null)
    return this.x509Info_.getSignatureValue();

  return this.getSignature().getSignature();
};

// TODO: getExtension

/**
 * Override to call the base class wireDecode then check the certificate format.
 * If the input is an X.509 certificate, then encapsulate it.
 * @param {Blob|Buffer} input The buffer with the bytes to decode.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to decode
 * this object. If omitted, use WireFormat.getDefaultWireFormat().
 */
CertificateV2.prototype.wireDecode = function(input, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  if (!(input instanceof Blob))
    input = new Blob(input, true);
  if (input.size() >= 1 && input.buf()[0] === DerNodeType.Sequence) {
    // Replace the input with a Data packet that encapsulates the X.509 certificate.
    // Set the subject name. All other fields are accessed by getIssuerName, etc.
    var x509Info = new X509CertificateInfo(input);
    var data = new Data(x509Info.getSubjectName());
    data.setContent(input);
    data.getMetaInfo().setType(ContentType.KEY);
    data.getMetaInfo().setFreshnessPeriod(3600 * 1000.0);

    // Set a digest signature.
    data.setSignature(new DigestSha256Signature());
    // Encode once to get the signed portion.
    var encoding = data.wireEncode(wireFormat);
    // Compute the SHA-256 here so that we don't depend on KeyChain.
    var digest = Crypto.createHash('sha256');
    digest.update(encoding.signedBuf());
    data.getSignature().setSignature(new Blob(digest.digest(), false));

    input = data.wireEncode(wireFormat);
    // Proceed below to re-decode from the encapsulated content.
  }

  Data.prototype.wireDecode.call(this, input, wireFormat);
  this.checkFormat_();

  if (this.getSignature() instanceof DigestSha256Signature) {
    // The signature is DigestSha256. Try to decode the content as an X.509 certificate.
    try {
      this.x509Info_ = new X509CertificateInfo(this.getContent());
    } catch (ex) {
      // The content doesn't seem to be an X.509 certificate. Ignore.
    }
  }
};

/**
 * Get a string representation of this certificate.
 * @return {string} The string representation.
 */
CertificateV2.prototype.toString = function()
{
  var result = "";
  result += "Certificate name:\n";
  result += "  " + this.getName().toUri() + "\n";
  result += "Validity:\n";
  result += "  NotBefore: " + WireFormat.toIsoString
    (this.getValidityPeriod().getNotBefore()) + "\n";
  result += "  NotAfter: " + WireFormat.toIsoString
    (this.getValidityPeriod().getNotAfter()) + "\n";

  // TODO: Print the extension.

  result += "Public key bits:\n";
  try {
    var keyBase64 = this.getPublicKey().buf().toString('base64');
    for (var i = 0; i < keyBase64.length; i += 64)
      result += (keyBase64.substr(i, 64) + "\n");
  } catch (ex) {
    // No public key.
  }

  result += "Signature Information:\n";
  result += "  Signature Type: ";
  if (this.getSignature() instanceof Sha256WithEcdsaSignature)
    result += "SignatureSha256WithEcdsa\n";
  else if (this.getSignature() instanceof Sha256WithRsaSignature)
    result += "SignatureSha256WithRsa\n";
  else
    result += "<unknown>\n";

  if (KeyLocator.canGetFromSignature(this.getSignature())) {
    result += "  Key Locator: ";
    var keyLocator = KeyLocator.getFromSignature(this.getSignature());
    if (keyLocator.getType() == KeyLocatorType.KEYNAME) {
      if (keyLocator.getKeyName().equals(this.getKeyName()))
        result += "Self-Signed ";

      result += "Name=" + keyLocator.getKeyName().toUri() + "\n";
    }
    else
      result += "<no KeyLocator key name>\n";
  }

  return result;
};

/**
 * Check if certificateName follows the naming convention for a certificate.
 * @param {Name} certificateName The name of the certificate.
 * @return {boolean} True if certificateName follows the naming convention.
 */
CertificateV2.isValidName = function(certificateName)
{
  if (X509CertificateInfo.isEncapsulatedX509(certificateName))
    // This is an X.509 name from an encapsulated certificate, so don't check it.
    return true;

  // /<NameSpace>/KEY/[KeyId]/[IssuerId]/[Version]
  return (certificateName.size() >= CertificateV2.MIN_CERT_NAME_LENGTH &&
          certificateName.get(CertificateV2.KEY_COMPONENT_OFFSET).equals
            (CertificateV2.KEY_COMPONENT));
};

/**
 * Extract the identity namespace from certificateName.
 * @param {Name} certificateName The name of the certificate.
 * @return {Name} The identity namespace as a new Name.
 */
CertificateV2.extractIdentityFromCertName = function(certificateName)
{
  if (!CertificateV2.isValidName(certificateName))
    throw new InvalidArgumentException(new Error
      ("Certificate name `" + certificateName.toUri() +
        "` does not follow the naming conventions"));

  return certificateName.getPrefix(CertificateV2.KEY_COMPONENT_OFFSET);
};

/**
 * Extract key name from certificateName.
 * @param {Name} certificateName The name of the certificate.
 * @return {Name} The key name as a new Name.
 */
CertificateV2.extractKeyNameFromCertName = function(certificateName)
{
  if (!CertificateV2.isValidName(certificateName)) {
    throw new InvalidArgumentException(new Error
      ("Certificate name `" + certificateName.toUri() +
        "` does not follow the naming conventions"));
  }

  // Trim everything after the key ID.
  return certificateName.getPrefix(CertificateV2.KEY_ID_OFFSET + 1);
};

CertificateV2.VERSION_OFFSET = -1;
CertificateV2.ISSUER_ID_OFFSET = -2;
CertificateV2.KEY_ID_OFFSET = -3;
CertificateV2.KEY_COMPONENT_OFFSET = -4;
CertificateV2.MIN_CERT_NAME_LENGTH = 4;
CertificateV2.MIN_KEY_NAME_LENGTH = 2;
CertificateV2.KEY_COMPONENT = new Name.Component("KEY");

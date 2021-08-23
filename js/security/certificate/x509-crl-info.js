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
var X509CertificateInfo = require('./x509-certificate-info.js').X509CertificateInfo; /** @ignore */
var DerNode = require('../../encoding/der/der-node.js').DerNode;

/**
 * An X509CrlInfo holds the fields from decoding an X.509 Certificate Revocation
 * List (CRL).
 *
 * There are two forms of the constructor:
 * X509CrlInfo(encoding) - Create an X509CrlInfo by decoding an X.509 CRL.
 * X509CrlInfo(crlInfo) - Create an X509CrlInfo, copying values from the other object.
 * @param {Blob} encoding The encoded X.509 CRL.
 * @param {X509CrlInfo} crlInfo The other X509CrlInfo to copy from.
 * @throws Error for error decoding the CRL.
 * @constructor
 */
var X509CrlInfo = function X509CrlInfo(encoding)
{
  if (typeof encoding === 'object' && encoding instanceof X509CrlInfo) {
    // The copy constructor.
    crlInfo = encoding;

    this.root_ = crlInfo.root_;
    this.signatureValue_ = crlInfo.signatureValue_;
    this.signedEncoding_ = crlInfo.signedEncoding_;
    this.issuerName_ = new Name(crlInfo.issuerName_);
    this.thisUpdate_ = crlInfo.thisUpdate_;
    this.nextUpdate_ = crlInfo.nextUpdate_;
    // Copy the RevokedCertificate entries.
    this.revokedCertificates_ = [];
    for (var i = 0; i < crlInfo.revokedCertificates_.length; ++i)
      this.revokedCertificates_.push
        (new X509CrlInfo.RevokedCertificate
         (crlInfo.revokedCertificates_[i].serialNumber_,
          crlInfo.revokedCertificates_[i].revocationDate_));

    return;
  }

  // See https://tools.ietf.org/html/rfc5280 .
  // CertificateList  ::=  SEQUENCE  {
  //       tbsCertList          TBSCertList,
  //       signatureAlgorithm   AlgorithmIdentifier,
  //       signatureValue       BIT STRING  }
  var tbsCertList;
  var signatureAlgorithm;
  try {
    this.root_ = DerNode.parse(encoding);
    var rootChildren = this.root_.getChildren();
    if (rootChildren.length < 3)
      throw new Error("X509CrlInfo: Expected 3 CRL fields");
    tbsCertList = DerNode.getSequence(rootChildren, 0);
    signatureAlgorithm = DerNode.getSequence(rootChildren, 1);
    var signatureValueNode = rootChildren[2];

    // Expect the first byte of the BIT STRING to be zero.
    if (!(signatureValueNode instanceof DerNode.DerBitString) ||
        signatureValueNode.getPayload().size() < 1 ||
        signatureValueNode.getPayload().buf()[0] != 0)
      throw new Error("X509CrlInfo: Cannot decode signatureValue");
    this.signatureValue_ = new Blob
      (signatureValueNode.getPayload().buf().slice(1, signatureValueNode.getPayload().size()));

    // Get the signed portion.
    var beginOffset = this.root_.getHeaderSize();
    var endOffset = beginOffset + tbsCertList.getSize();
    this.signedEncoding_ = new SignedBlob(encoding, beginOffset, endOffset);
  } catch (ex) {
    throw new Error("X509CrlInfo: Cannot decode CRL: " + ex);
  }

  // TBSCertList  ::=  SEQUENCE  {
  //      version                 Version OPTIONAL,
  //                                   -- if present, MUST be v2
  //      signature               AlgorithmIdentifier,
  //      issuer                  Name,
  //      thisUpdate              Time,
  //      nextUpdate              Time OPTIONAL,
  //      revokedCertificates     SEQUENCE OF SEQUENCE  {
  //           userCertificate         CertificateSerialNumber,
  //           revocationDate          Time,
  //           crlEntryExtensions      Extensions OPTIONAL
  //                                    -- if present, version MUST be v2
  //                                }  OPTIONAL,
  //      crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
  //                                    -- if present, version MUST be v2
  //                                }
  try {
    var tbsChildren = tbsCertList.getChildren();

    var versionOffset = 0;
    if (tbsChildren.length >= 1 && tbsChildren[0] instanceof DerNode.DerInteger)
      // There is a version.
      versionOffset = 1;
    if (tbsChildren.length < 5 + versionOffset)
      throw new Error("X509CrlInfo: Expected 5 TBSCertList fields");

    this.issuerName_ = X509CertificateInfo.makeName
      (tbsChildren[1 + versionOffset], null);

    // Get thisUpdate and nextUpdate.
    var thisUpdate = tbsChildren[2 + versionOffset];
    var nextUpdate = tbsChildren[3 + versionOffset];
    if (!(thisUpdate instanceof DerNode.DerUtcTime) ||
        !(nextUpdate instanceof DerNode.DerUtcTime))
      throw new Error("X509CrlInfo: Cannot decode thisUpdate and nextUpdate");
    this.thisUpdate_ = thisUpdate.toVal();
    this.nextUpdate_ = nextUpdate.toVal();

    // Get the revoked certificate entries.
    var revokedCertificatesChildren = tbsChildren[4 + versionOffset].getChildren();
    this.revokedCertificates_ = [];
    for (var i = 0; i < revokedCertificatesChildren.length; ++i) {
      var revokedCertificate = revokedCertificatesChildren[i];
      if (!(revokedCertificate instanceof DerNode.DerSequence))
        // We don't expect this.
        continue;
      var revokedCertificateChildren = revokedCertificate.getChildren();
      if (revokedCertificateChildren.length < 2)
        throw new Error("X509CrlInfo: Cannot decode revokedCertificate sequence");

      var serialNumber = revokedCertificateChildren[0];
      if (!(serialNumber instanceof DerNode.DerInteger))
        throw new Error("X509CrlInfo: Cannot get serial number from revokedCertificate");
      var revocationDate = revokedCertificateChildren[1];
      if (!(revocationDate instanceof DerNode.DerUtcTime))
        throw new Error("X509CrlInfo: Cannot get revocation date from revokedCertificate");

      this.revokedCertificates_.push
        (new X509CrlInfo.RevokedCertificate
         (serialNumber.getPayload(), revocationDate.toVal()));
    }

    // For now, ignore the extensions.
  } catch (ex) {
    throw new Error("X509CrlInfo: Cannot decode the TBSCertificate: " + ex);
  }
};

exports.X509CrlInfo = X509CrlInfo;

/**
 * An X509CrlInfo.RevokedCertificate holds the serial number and other
 * information in the entry of a CRL's list of revoked certificates.
 * Create an X509CrlInfo.RevokedCertificate with the given values.
 * @param {Blob} serialNumber The revoked certificate's serial number as a Blob
 * with the bytes of the integer.
 * @param {number} revocationDate The revocation date as milliseconds since
 * Jan 1, 1970 UTC.
 * @constructor
 */
X509CrlInfo.RevokedCertificate = function X509CrlInfoRevokedCertificate
  (serialNumber, revocationDate)
{
  this.serialNumber_ = serialNumber;
  this.revocationDate_ = revocationDate;
};

/**
 * Get this entry's serial number.
 * @return {number} The serial number as a Blob with the bytes of the integer.
 */
X509CrlInfo.RevokedCertificate.prototype.getSerialNumber = function()
{
  return this.serialNumber_;
};

/**
 * Get this entry's revocation date.
 * @return {number} The revocation date as milliseconds since Jan 1, 1970 UTC.
 */
X509CrlInfo.RevokedCertificate.prototype.getRevocationDate = function()
{
  return this.revocationDate_;
};

/**
 * Get the SignedBlob of the encoding with the offsets for the signed portion.
 * @return {SignedBlob} The SignedBlob of the encoding.
 */
X509CrlInfo.prototype.getEncoding = function()
{
  return this.signedEncoding_;
};

/**
 * Get the issuer name which has been converted to an NDN name.
 * @return {Name} The issuer name.
 */
X509CrlInfo.prototype.getIssuerName = function() { return this.issuerName_; };

/**
 * Get the thisUpdate time.
 * @return {number} The thisUpdate time as milliseconds since Jan 1, 1970 UTC.
 */
X509CrlInfo.prototype.getThisUpdate = function() { return this.thisUpdate_; };

/**
 * Get the nextUpdate time.
 * @return {number} The nextUpdate time as milliseconds since Jan 1, 1970 UTC.
 */
X509CrlInfo.prototype.getNextUpdate = function() { return this.nextUpdate_; };

/**
 * Get the number of entries in the revoked certificates list.
 * @return {number} The number of revoked certificate entries.
 */
X509CrlInfo.prototype.getRevokedCertificateCount = function()
{
  return this.revokedCertificates_.length;
};

/**
 * Get the revoked certificate entry at the given index.
 * @return {number} i The index of the revoked certificate entry, starting from 0.
 * @return {X509CrlInfo.RevokedCertificate} The entry at the index.
 */
X509CrlInfo.prototype.getRevokedCertificate = function(i)
{
  return this.revokedCertificates_[i];
};

/**
 * Get the signature value bytes.
 * @return {Blob} The signature value.
 */
X509CrlInfo.prototype.getSignatureValue = function()
{
  return this.signatureValue_;
};

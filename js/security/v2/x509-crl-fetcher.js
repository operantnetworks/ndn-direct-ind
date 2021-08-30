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

/** @ignore */
var Blob = require('../../util/blob.js').Blob; /** @ignore */
var Name = require('../../name.js').Name; /** @ignore */
var Interest = require('../../interest.js').Interest; /** @ignore */
var X509CrlInfo = require('../certificate/x509-crl-info.js').X509CrlInfo; /** @ignore */
var VerificationHelpers = require('../verification-helpers.js').VerificationHelpers; /** @ignore */
var LOG = require('../../log.js').Log.LOG;

/**
 * An X509CrlFetcher sends periodic Interests to fetch the latest embedded X.509
 * CRL for a particular issuer from a particular CRL publisher (whose prefix is
 * different from the CRL issuer). See the constructor for details.
 *
 * Create an X509CrlFetcher for the given issuer and publisher prefix. This
 * immediately uses the Face to send the first _latest Interest to the CRL
 * publisher: <crlPublisherPrefix>/crl/<issuerName>/_latest . When a new
 * CRL arrives and is validated, call validator.cacheVerifiedCrl which will
 * evict any certificates on the revocation list and will save the CRL for
 * checking if new certificates are revoked. (Note that cacheVerifiedCrl is
 * a method of CertificateStorage which is a base class of Validator.) You
 * must create an X509CrlFetcher object (separate from the Validator) which
 * must remain valid for the duration of your application. If you want to
 * delete the X509CrlFetcher before the end of your application, you should
 * call shutdown().
 * @param {Name} issuerName The encapsulated X.509 issuer name of the CRL.
 * @param {Name} crlPublisherPrefix The NDN prefix for sending _latest Interests
 * and Interests to fetch the CRL. (This is different from the CRL issuer which
 * is an encapsulated X.509 name and not routable.)
 * @param {Face} face The Face for sending Interests.
 * @param {Validator} validator The Validator for checking the signature on the
 * _latest Data packet from the CRL publisher, and for getting the CRL issuer's
 * public key, and for calling cacheVerifiedCrl.
 * @param {number} checkForNewCrlInterval The interval in milliseconds between
 * sending a _latest Interest to the CRL publisher to check for a new CRL.
 * @param {number} noResponseWarningInterval If there is no response from the CRL
 * publisher after this number of milliseconds, log a message each time the
 * Interest times out.
 * @constructor
 */
var X509CrlFetcher = function X509CrlFetcher
  (issuerName, crlPublisherPrefix, face, validator, checkForNewCrlInterval,
   noResponseWarningInterval)
{
  // Copy the Name.
  this.issuerName_ = new Name(issuerName),
  this.face_ = face;
  this.crlPublisherPrefix_ = new Name(crlPublisherPrefix);
  this.validator_ = validator;
  this.checkForNewCrlInterval_ = checkForNewCrlInterval;
  this.noResponseWarningInterval_ = noResponseWarningInterval;
  this.currentCrlName_ = new Name();
  this.isCrlRetrievalInProgress_ = false;
  this.isEnabled_ = true;
  this.crlPendingInterestId_ = 0;

  this.crlLatestPrefix_ = new Name(crlPublisherPrefix)
    .append("crl")
    .append(issuerName.wireEncode())
    .append("_latest");
  this.lastResponseTime_ = new Date().getTime();

  this.checkForNewCrl_();
};

exports.X509CrlFetcher = X509CrlFetcher;

/**
 * Get the issuer name for this CRL manager.
 * @return {Name} The issuer Name. You should not modify this Name.
 */
X509CrlFetcher.prototype.getIssuerName = function() { return this.issuerName_; }

X509CrlFetcher.prototype.shutdown = function()
{
  this.isEnabled_ = false;
  if (this.crlPendingInterestId_ > 0)
    this.face_.removePendingInterest(crlPendingInterestId_);
};

/**
 * Send an interest for the crlLatestPrefix_ to get the name of the latest
 * CRL, and schedule sending the next one after checkForNewCrlInterval_.
 * If it doesn't match currentCrlName_, then call fetchCrl().
 */
X509CrlFetcher.prototype.checkForNewCrl_ = function()
{
  if (!this.isEnabled_)
    // shutdown() set this false.
    return;

  // Schedule the next check now.
  var thisFetcher = this;
  setTimeout
    (function() { thisFetcher.checkForNewCrl_(); }, this.checkForNewCrlInterval_);

  if (this.isCrlRetrievalInProgress_)
    // Already checking.
    return;
  this.isCrlRetrievalInProgress_ = true;

  var onData = function(interest, crlLatestData) {
    thisFetcher.lastResponseTime_ = new Date().getTime();

    // Validate the Data signature.
    thisFetcher.validator_.validate(
      crlLatestData,
      function(d) {
        var newCrlName = new Name();
        try {
          newCrlName.wireDecode(crlLatestData.getContent());
        } catch (ex) {
          thisFetcher.isCrlRetrievalInProgress_ = false;
          if (LOG > 1) console.log("Error decoding CRL name in: " +
            crlLatestData.getName().toUri());
          return;
        }

        if (newCrlName.equals(thisFetcher.currentCrlName_)) {
          // The latest is the same name, so do nothing.
          if (LOG > 3)("Got CRL _latest response with same CRL name: " +
            newCrlName.toUri());
          thisFetcher.isCrlRetrievalInProgress_ = false;
          return;
        }

        // Leave isCrlRetrievalInProgress_ true.
        thisFetcher.fetchCrl_(newCrlName, 0, X509CrlFetcher.N_RETRIES, []);
      },
      function(d, error) {
        thisFetcher.isCrlRetrievalInProgress_ = false;
        if (LOG > 1) console.log("Validate CRL _latest Data failure: " +
          error.toString());
      });
  };

  var onTimeout = function(interest) {
    thisFetcher.isCrlRetrievalInProgress_ = false;
    if (LOG > 1) console.log("Timeout for CRL _latest packet: " +
      interest.getName().toUri());
    thisFetcher.maybeLogResponseWarning_();
  };

  var onNetworkNack = function(interest, networkNack) {
    thisFetcher.isCrlRetrievalInProgress_ = false;
    if (LOG > 1) console.log("Network nack for CRL _latest packet: " +
      interest.getName().toUri() + ". Got NACK (" + networkNack.getReason() + ")");
    thisFetcher.maybeLogResponseWarning_();
  };

  try {
    this.face_.expressInterest
      (new Interest(this.crlLatestPrefix_).setMustBeFresh(true).setCanBePrefix(true),
       onData, onTimeout, onNetworkNack);
  } catch (ex) {
    thisFetcher.isCrlRetrievalInProgress_ = false;
    if (LOG > 1) console.log("expressInterest error: " + ex);
  }
};

/**
 * Fetch the segment Data packets <newCrlName>/<segment> .  We don't expect
 * the CRL to have too many segments or need to be fetched with millisecond
 * efficiency, so fetch segments one at a time.
 * @param {Name} newCrlName The name of the CRL to fetch.
 * @param {number} expectedSegment The expected segment number. On the first
 * call, use 0.
 * @param {number} nTriesLeft If fetching times out, decrement nTriesLeft and try
 * again until it is zero.
 * @param {Array<Buffer>} segments An array where we append each segment Buffer
 * as it comes in. On the first call, use [] .
 */
X509CrlFetcher.prototype.fetchCrl_ = function
  (newCrlName, expectedSegment, nTriesLeft, segments)
{
  var crlSegmentName = new Name(newCrlName);
  crlSegmentName.appendSegment(expectedSegment);

  if (LOG > 3) console.log("Fetching CRL segment " + crlSegmentName.toUri());

  var thisFetcher = this;
  var onData = function(crlSegmentInterest, segmentData) {
    try {
      thisFetcher.crlPendingInterestId_ = 0;
      thisFetcher.lastResponseTime_ = new Date().getTime();

      if (!segmentData.getName().get(-1).isSegment()) {
        thisFetcher.isCrlRetrievalInProgress_ = false;
        if (LOG > 1) console.log(
          "fetchCrl: The CRL segment Data packet name does not end in a segment: " +
          segmentData.getName().toUri());
        return;
      }
      var segment = segmentData.getName().get(-1).toSegment();
      if (segment != expectedSegment) {
        // Since we fetch in sequence, we don't expect this.
        thisFetcher.isCrlRetrievalInProgress_ = false;
        if (LOG > 1) console.log("fetchCrl: Expected segment " + expectedSegment +
          ", but got " + segmentData.getName().toUri());
        return;
      }

      var finalBlockId = -1;
      if (segmentData.getMetaInfo().getFinalBlockId().getValue().size() > 0)
        finalBlockId = segmentData.getMetaInfo().getFinalBlockId().toSegment();
      if (segment == finalBlockId) {
        // Finished. Concatenate the CRL segments.
        segments.push(segmentData.getContent().buf());
        var buffer = Buffer.concat(segments);

        // Decode and process the CRL.
        // Leave isCrlRetrievalInProgress_ true.
        thisFetcher.validateAndProcessNewCrl_
          (newCrlName, new X509CrlInfo(new Blob(buffer, false)));

        // This CRL has been processed, so allow checking for new CRLs.
        thisFetcher.isCrlRetrievalInProgress_ = false;
        return;
      }

      // Save the segment and fetch the next one.
      segments.push(segmentData.getContent().buf());
      thisFetcher.fetchCrl_
        (newCrlName, expectedSegment + 1, X509CrlFetcher.N_RETRIES, segments);
    } catch (ex) {
      thisFetcher.isCrlRetrievalInProgress_ = false;
      if (LOG > 1) console.log("Error in fetchCrl onData: " + ex);
    }
  };

  var onTimeout = function(interest) {
    thisFetcher.crlPendingInterestId_ = 0;
    if (nTriesLeft > 1)
      thisFetcher.fetchCrl_
        (newCrlName, expectedSegment, nTriesLeft - 1, segments);
    else {
      thisFetcher.isCrlRetrievalInProgress_ = false;
      if (LOG > 1) console.log("Retrieval of CRL segment [" +
        interest.getName().toUri() + "] timed out");
      thisFetcher.maybeLogResponseWarning_();
    }
  };

  var onNetworkNack = function(interest, networkNack) {
    thisFetcher.crlPendingInterestId_ = 0;
    thisFetcher.isCrlRetrievalInProgress_ = false;
    if (LOG > 1) console.log("Retrieval of CRL segment [" +
      interest.getName().toUri() + "] failed. Got NACK (" +
      networkNack.getReason() << ")");
    thisFetcher.maybeLogResponseWarning_();
  };

  try {
    this.crlPendingInterestId_ = this.face_.expressInterest
      (new Interest(crlSegmentName).setMustBeFresh(false).setCanBePrefix(true),
       onData, onTimeout, onNetworkNack);
  } catch (ex) {
    thisFetcher.isCrlRetrievalInProgress_ = false;
    if (LOG > 1) console.log("expressInterest error: " + ex);
  }
};

/**
 * Validate the CRL signature, then set currentCrlName_ to newCrlName.
 * @param {Name} newCrlName The name of the CRL that was fetched.
 * @param {X509CrlInfo} crlInfo The X509CrlInfo of the fetched and decoded CRL.
 */
X509CrlFetcher.prototype.validateAndProcessNewCrl_ = function(newCrlName, crlInfo)
{
  if (!crlInfo.getIssuerName().equals(this.issuerName_)) {
    // This shouldn't happen, but we check anyway.
    if (LOG > 1) console.log(
      "The fetched CRL issuer name is not the expected name: Not adding CRL from issuer " +
      crlInfo.getIssuerName().toUri());
    return;
  }

  // Right now, we only support a CRL which is signed by a trust anchor because
  // the issuer name is an encapsulated X.509 name and not routable, so it must
  // already be present as the trust anchor.
  // Get the issuer certificate (the self-signed trust anchor) and use it to
  // validate the CRL.
  var issuerCertificate = this.validator_.getTrustAnchors().find(crlInfo.getIssuerName());
  if (issuerCertificate == null) {
    // This shouldn't happen, but we check anyway.
    if (LOG > 1) console.log(
      "CRL issuer's certificate is not in the trust anchors: Not adding CRL from issuer " +
      crlInfo.getIssuerName().toUri());
    return;
  }
  // For a public key operation, we can use the async version.
  if (!VerificationHelpers.verifySignature
      (crlInfo.getEncoding().signedBuf(), crlInfo.getSignatureValue().buf(),
       issuerCertificate.getPublicKey())) {
    if (LOG > 1) console.log(
      "CRL signature validation failure: Not adding CRL from issuer " +
      crlInfo.getIssuerName().toUri());
    return;
  }

  // The CRL signature is valid. Save the current name, meaning that we have
  // successfully fetched it from the CRL publisher. cacheVerifiedCrl may
  // discover that the CRL has a bad validity period but that is not our
  // concern here. No matter what, we will just wait for a new version from the
  // CRL publisher.
  this.currentCrlName_ = newCrlName;

  // cacheVerifiedCrl checks the CRL validity period, saves the CRL and checks
  // if currently stored certificates are revoked.
  // This copies the crlInfo.
  this.validator_.cacheVerifiedCrl(crlInfo);
};

/**
 * This is called on a timeout or network nack from the publisher to log a
 * warning if more than noResponseWarningInterval_ has elapsed since
 * lastResponseTime_ .
 */
X509CrlFetcher.prototype.maybeLogResponseWarning_ = function()
{
  var elapsed = new Date().getTime() - this.lastResponseTime_;
  if (elapsed > this.noResponseWarningInterval_)
    consoler.log("CRL ALARM: No response in " + (elapsed / (3600.0 * 1000.0)) +
      " hours from the CRL publisher at " + this.crlPublisherPrefix_.toUri());
};

X509CrlFetcher.N_RETRIES = 3;

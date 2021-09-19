/**
 * Copyright (C) 2021 Operant Networks, Incorporated.
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: js/security/v2/data-calidation-state.js
 * Original repository: https://github.com/named-data/ndn-js
 *
 * Summary of Changes: Store data as CertificateV2 if needed.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2018-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/v2/validation-state.hpp
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
var SyncPromise = require('../../util/sync-promise.js').SyncPromise; /** @ignore */
var Data = require('../../data.js').Data; /** @ignore */
var LOG = require('../../log.js').Log.LOG; /** @ignore */
var CertificateV2 = require('./certificate-v2.js').CertificateV2; /** @ignore */
var ValidationError = require('./validation-error.js').ValidationError; /** @ignore */
var ValidationState = require('./validation-state.js').ValidationState; /** @ignore */
var VerificationHelpers = require('../verification-helpers.js').VerificationHelpers; /** @ignore */
var WireFormat = require('../../encoding/wire-format.js').WireFormat; /** @ignore */
var NdnCommon = require('../../util/ndn-common.js').NdnCommon;

/**
 * The DataValidationState class extends ValidationState to hold the validation
 * state for a Data packet.
 *
 * Create a DataValidationState for the Data packet. The caller must ensure that
 * the state instance is valid until the validation finishes (i.e., until
 * validateCertificateChain() and validateOriginalPacket() have been called).
 * @param {Data} data The Date packet being validated, which is copied.
 * @param {function} successCallback This calls successCallback(data) to report
 * a successful Data validation.
 * @param {function} failureCallback This calls failureCallback(data, error) to
 * report a failed Data validation, where error is a ValidationError.
 * @constructor
 */
var DataValidationState = function DataValidationState
  (data, successCallback, failureCallback)
{
  // Call the base constructor.
  ValidationState.call(this);

  // Make a copy.
  if (data instanceof CertificateV2)
    this.data_ = new CertificateV2(data);
  else
    this.data_ = new Data(data);
  this.successCallback_ = successCallback;
  this.failureCallback_ = failureCallback;

  if (this.successCallback_ == null)
    throw new Error("The successCallback is null");
  if (this.failureCallback_ == null)
    throw new Error("The failureCallback is null");
};

DataValidationState.prototype = new ValidationState();
DataValidationState.prototype.name = "DataValidationState";

exports.DataValidationState = DataValidationState;

/**
 * Call the failure callback.
 * @param {ValidationError} error
 */
DataValidationState.prototype.fail = function(error)
{
  if (LOG > 3) console.log("" + error);
  try {
    this.failureCallback_(this.data_, error);
  } catch (ex) {
    console.log("Error in failureCallback: " + NdnCommon.getErrorWithStackTrace(ex));
  }
  this.setOutcome(false);
};

/**
 * Get the original Data packet being validated which was given to the
 * constructor.
 * @return {Data} The original Data packet.
 */
DataValidationState.prototype.getOriginalData = function() { return this.data_; };

/**
 * Override to verify the Data packet given to the constructor.
 * @param {CertificateV2} trustedCertificate The certificate that signs the
 * original packet.
 * @param {CertificateStorage} certificateStorage If not null and the original
 * packet is a CertificateV2, call certificateStorage.findRevokedCertificate to
 * check if the original packet is revoked.
 * @return {Promise|SyncPromise} A promise that resolves when the success or
 * failure callback has been called.
 */
DataValidationState.prototype.verifyOriginalPacketPromise_ = function
  (trustedCertificate, certificateStorage)
{
  var thisState = this;

  return VerificationHelpers.verifyDataSignaturePromise
    (this.data_, trustedCertificate)
  .then(function(verifySuccess) {
    if (verifySuccess) {
      if (certificateStorage != null && thisState.data_ instanceof CertificateV2) {
        var originalCertificate = thisState.data_;
        // The original packet is a certificate. Check if the issuer has revoked it.
        var revoked = certificateStorage.findRevokedCertificate
          (originalCertificate.getIssuerName(), originalCertificate.getX509SerialNumber());
        if (revoked != null) {
          thisState.fail(new ValidationError(ValidationError.REVOKED,
            "The CRL from issuer " + originalCertificate.getIssuerName().toUri() +
            " has revoked serial number " + revoked.getSerialNumber().toHex() +
            " at time " + WireFormat.toIsoString(revoked.getRevocationDate()) +
            ". Rejecting certificate " + originalCertificate.getName().toUri()));
          return SyncPromise.resolve();
        }
      }

      if (LOG > 3) console.log("OK signature for data `" +
        thisState.data_.getName().toUri() + "`");
      try {
        thisState.successCallback_(thisState.data_);
      } catch (ex) {
        console.log("Error in successCallback: " + NdnCommon.getErrorWithStackTrace(ex));
      }
      thisState.setOutcome(true);
    }
    else
      thisState.fail(new ValidationError(ValidationError.INVALID_SIGNATURE,
        "Invalid signature of data `" + thisState.data_.getName().toUri() + "`"));

    return SyncPromise.resolve();
  });
};

/**
 * Override to call the success callback using the Data packet given to the
 * constructor.
 */
DataValidationState.prototype.bypassValidation_ = function()
{
  if (LOG > 3) console.log("Signature verification bypassed for data `" +
    this.data_.getName().toUri() + "`");
  try {
    this.successCallback_(this.data_);
  } catch (ex) {
    console.log("Error in successCallback: " + NdnCommon.getErrorWithStackTrace(ex));
  }
  this.setOutcome(true);
};

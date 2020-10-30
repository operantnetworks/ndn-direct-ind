/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: js/encrypt/encryptor-v2.js
 * Original repository: https://github.com/named-data/ndn-js
 *
 * Summary of Changes: Support GCK, async TPM.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From the NAC library https://github.com/named-data/name-based-access-control/blob/new/src/encryptor.cpp
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
var Crypto = require('../crypto.js'); /** @ignore */
var Blob = require('../util/blob.js').Blob; /** @ignore */
var Name = require('../name.js').Name; /** @ignore */
var Data = require('../data.js').Data; /** @ignore */
var Interest = require('../interest.js').Interest; /** @ignore */
var SigningInfo = require('../security/signing-info.js').SigningInfo; /** @ignore */
var InMemoryStorageRetaining = require('../in-memory-storage/in-memory-storage-retaining.js').InMemoryStorageRetaining; /** @ignore */
var PublicKey = require('../security/certificate/public-key.js').PublicKey; /** @ignore */
var EncryptedContent = require('./encrypted-content.js').EncryptedContent; /** @ignore */
var EncryptParams = require('./algo/encrypt-params.js').EncryptParams; /** @ignore */
var EncryptAlgorithmType = require('./algo/encrypt-params.js').EncryptAlgorithmType; /** @ignore */
var AesAlgorithm = require('./algo/aes-algorithm.js').AesAlgorithm; /** @ignore */
var NdnCommon = require('../util/ndn-common.js').NdnCommon; /** @ignore */
var EncryptError = require('./encrypt-error.js').EncryptError; /** @ignore */
var WireFormat = require('../encoding/wire-format.js').WireFormat; /** @ignore */
var SyncPromise = require('../util/sync-promise.js').SyncPromise; /** @ignore */
var LOG = require('../log.js').Log.LOG;

/**
 * EncryptorV2 encrypts the requested content for name-based access control (NAC)
 * using security v2. For the meaning of "KEK", etc. see:
 * https://github.com/named-data/name-based-access-control/blob/new/docs/spec.rst
 *
 * There are two forms of the constructor:
 * EncryptorV2(accessPrefix, ckPrefix, ckDataSigningInfo, onError, validator, keyChain, face) -
 * Create an EncryptorV2 for encrypting using a group KEK and KDKs. This uses
 * the face to register to receive Interests for the prefix {ckPrefix}/CK.
 * EncryptorV2(accessPrefix, onError, credentialsKey, validator, keyChain, face) -
 * Create an EncryptorV2 for encrypting using a group content key (GCK) which
 * is provided by the access manager.
 * @param {Name} accessPrefix The NAC prefix to fetch the Key Encryption Key
 * (KEK) (e.g., /access/prefix/NAC/data/subset). This copies the Name.
 * @param {Name} ckPrefix The prefix under which Content Keys (CK) will be
 * generated. (Each will have a unique version appended.) This copies the Name.
 * @param {SigningInfo} ckDataSigningInfo The SigningInfo parameters to sign the
 * Content Key (CK) Data packet. This copies the SigningInfo.
 * @param {function} onError On failure to create the CK data (failed to fetch
 * the KEK, failed to encrypt with the KEK, etc.), this calls
 * onError(errorCode, message) where errorCode is from
 * EncryptError.ErrorCode, and message is an error string. The encrypt
 * method will continue trying to retrieve the KEK until success (with each
 * attempt separated by RETRY_DELAY_KEK_RETRIEVAL_MS) and onError may be
 * called multiple times.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {PibKey} credentialsKey The credentials key to be used to retrieve and
 * decrypt the GCK.
 * @param {Validator} validator The validation policy to ensure correctness of
 * the KEK.
 * @param {KeyChain} keyChain The KeyChain used to sign Data packets.
 * @param {Face} face The Face that will be used to fetch the KEK and publish CK data.
 * @constructor
 */
var EncryptorV2 = function EncryptorV2
  (accessPrefix, ckPrefix, ckDataSigningInfo, onError, validator, keyChain, face)
{
  var credentialsKey = null;
  if (typeof ckPrefix === 'function') {
    // This is the GCK constructor:
    // EncryptorV2(accessPrefix, onError, credentialsKey, validator, keyChain, face).
    var arg2 = ckPrefix;
    var arg3 = ckDataSigningInfo;
    var arg4 = onError;
    var arg5 = validator;
    var arg6 = keyChain;
    onError = arg2;
    credentialsKey = arg3;
    validator = arg4;
    keyChain = arg5;
    face = arg6;
  }

  // Copy the Name.
  this.accessPrefix_ = new Name(accessPrefix);
  // Generated CK name or fetched GCK name.
  this.ckName_ = new Name();
  // Generated CK (set by regenerateCk) or fetched GCK bits.
  this.ckBits_ = Buffer.alloc(EncryptorV2.AES_KEY_SIZE);
  this.onError_ = onError;

  // For creating CK Data packets. Not used for GCK.
  this.ckPrefix_ = new Name(ckPrefix);
  this.isKekRetrievalInProgress_ = false;
  this.kekData_ = null;
  this.ckDataSigningInfo_ = new SigningInfo(ckDataSigningInfo);

  // Storage for encrypted CKs. Not used for GCK.
  this.storage_ = new InMemoryStorageRetaining();
  this.ckRegisteredPrefixId_ = 0;
  this.kekPendingInterestId_ = 0;

  // For fetching and decrypting the GCK. Not used for CK.
  this.checkForNewGckIntervalMilliseconds_ = 60.0 * 1000;
  this.nextCheckForNewGck_ = 0;
  this.gckLatestPrefix_ = new Name();
  this.isGckRetrievalInProgress_ = false;
  this.gckPendingInterestId_ = 0;
  this.pendingEncrypts_ = [];
  this.credentialsKey_ = credentialsKey;

  this.validator_ = validator;
  this.keyChain_ = keyChain;
  this.face_ = face;

  if (credentialsKey != null)
    // Using GCK.
    this.gckLatestPrefix_ = new Name(this.accessPrefix_)
      .append(EncryptorV2.NAME_COMPONENT_GCK)
      .append(EncryptorV2.NAME_COMPONENT_LATEST);
  else
    this.initializeCk_();
};

/*
 * Complete the work of the constructor for a (non-group) content key.
 */
EncryptorV2.prototype.initializeCk_ = function()
{
  this.regenerateCk();

  var thisEncryptor = this;
  var onInterest = function(prefix, interest, face, interestFilterId, filter) {
    var data = thisEncryptor.storage_.find(interest);
    if (data != null) {
      if (LOG > 3) console.log
        ("Serving " + data.getName().toUri() + " from InMemoryStorage");
      try {
        face.putData(data);
      } catch (ex) {
        console.log("Error in Face.putData: " + NdnCommon.getErrorWithStackTrace(ex));
      }
    }
    else {
      if (LOG > 3) console.log
        ("Didn't find CK data for " + interest.getName().toUri());
      // TODO: Send NACK?
    }
  };

  var onRegisterFailed = function(prefix) {
    if (LOG > 0) console.log("Failed to register prefix " + prefix.toUri());
  };

  this.ckRegisteredPrefixId_ = this.face_.registerPrefix
    (new Name(this.ckPrefix_).append(EncryptorV2.NAME_COMPONENT_CK),
     onInterest, onRegisterFailed);
};

exports.EncryptorV2 = EncryptorV2;

EncryptorV2.prototype.shutdown = function()
{
  this.face_.unsetInterestFilter(this.ckRegisteredPrefixId_);
  if (this.kekPendingInterestId_ > 0)
    this.face_.removePendingInterest(this.kekPendingInterestId_);
  if (this.gckPendingInterestId_ > 0)
    this.face_.removePendingInterest(this.gckPendingInterestId_);
};

/**
 * There are four forms of the encrypt method:
 * encrypt(plainData) - Encrypt the plainData using the existing content key and
 * return a new EncryptedContent.
 * encrypt(plainData, onSuccess, onError) - Encrypt the plainData using the
 * existing content key and call the onSuccess callback with a new
 * EncryptedContent. On successful encryption, this calls
 * onSuccess(encryptedContent) where encryptedContent is the new
 * EncryptedContent. If this EncryptorV2 is using a group content key (GCK) then
 * this may fetch a new GCK before calling the onSuccess callback.
 * encrypt(data, onSuccess, onError) - Encrypt the Data packet content using the
 * existing content key and replace the content with the wire encoding of the
 * new EncryptedContent. On successful encryption, this calls
 * onSuccess(data, encryptedContent) where data is the the modified Data object
 * that was provided, and encryptedContent is the new EncryptedContent whose
 * encoding replaced the Data packet content. If this EncryptorV2 is using a 
 * group content key (GCK) then this may fetch a new GCK before calling the
 * onSuccess callback.
 * encrypt(interest, onSuccess, onError) - Encrypt the Interest
 * ApplicationParameters using the existing content key and replace the
 * ApplicationParameters with the wire encoding of the new EncryptedContent. On 
 * successful encryption, this calls onSuccess(interest, encryptedContent) where 
 * interest is the the modified Interest object that was provided, and 
 * encryptedContent is the new EncryptedContent whose encoding replaced the 
 * Interest ApplicationParameters. If this EncryptorV2 is using a group content
 * key (GCK) then this may fetch a new GCK before calling the onSuccess
 * callback. This appends a ParametersSha256Digest component to the Interest
 * name.
 * @param {Buffer|Blob} plainData The data to encrypt.
 * @param {Data} data The Data packet whose content is encrypted and replaced
 * with a new EncryptedContent. (This is also passed to the onSuccess callback.)
 * @param {Interest} interest The Interest whose ApplicationParameters is
 * encrypted and replaced with a new EncryptedContent. (This is also passed to
 * the onSuccess callback.)
 * @param {function} onSuccess On successful encryption, this calls the
 * onSuccess callback as decribed above.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) On failure, this calls
 * onError(errorCode, message) where errorCode is from EncryptError.ErrorCode,
 * and message is an error string. If omitted, call the onError given to the
 * constructor. (Even though the constructor has an onError, this is provided
 * separately since this asynchronous method completes either by calling
 * onSuccess or onError.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @return {EncryptedContent} (only for encrypt(plainData)) The new EncryptedContent.
 */
EncryptorV2.prototype.encrypt = function(plainData, onSuccess, onError)
{
  if (typeof onSuccess === 'function') {
    if (plainData instanceof Data) {
      var data = plainData;

      this.encrypt
        (data.getContent(),
         function(encryptedContent) {
           data.setContent(encryptedContent.wireEncodeV2());
           onSuccess(data, encryptedContent);
         },
         onError);
    }
    else if (plainData instanceof Interest) {
      var interest = plainData;

      if (interest.getName().findParametersSha256Digest() != -1) {
        onError(EncryptError.ErrorCode.EncryptionFailure,
          "The Interest name already has a ParametersSha256Digest component: " +
          interest.getName().toUri());
        return;
      }

      this.encrypt
        (interest.getApplicationParameters(),
         function(encryptedContent) {
           interest.setApplicationParameters(encryptedContent.wireEncodeV2());
           interest.appendParametersDigestToName();
           onSuccess(interest, encryptedContent);
         },
         onError);
    }
    else
      this.encryptSync_(plainData, onSuccess, onError);

    return;
  }

  if (this.isUsingGck_() && this.ckName_.size() == 0)
    throw new Error("EncryptorV2 has not fetched the first group content key (GCK)");

  // Generate the initial vector.
  var initialVector = Crypto.randomBytes(EncryptorV2.AES_IV_SIZE);

  var params = new EncryptParams(EncryptAlgorithmType.AesCbc);
  params.setInitialVector(new Blob(initialVector, false));
  if (!(plainData instanceof Blob))
    plainData = new Blob(plainData);
  // Debug: Use a Promise.
  var encryptedData = AesAlgorithm.encrypt
    (new Blob(this.ckBits_, false), plainData, params);

  var content = new EncryptedContent();
  content.setInitialVector(new Blob(initialVector, false));
  content.setPayload(encryptedData);
  content.setKeyLocatorName(this.ckName_);

  return content;
};

EncryptorV2.prototype.encryptSync_ = function(plainData, onSuccess, onError)
{
  // If the given OnError is omitted, use the one given to the constructor.
  if (!onError)
    onError = this.onError_;

  if (this.isUsingGck_()) {
    var now = new Date().getTime();

    if (this.ckName_.size() == 0) {
      // We haven't fetched the first GCK.
      if (LOG > 3) console.log
        ("The GCK is not yet available, so adding to the pending encrypt queue");
      this.pendingEncrypts_.push
        (new EncryptorV2.PendingEncrypt(plainData, onSuccess, onError));

      if (!this.isGckRetrievalInProgress_) {
        this.nextCheckForNewGck_ = now + this.checkForNewGckIntervalMilliseconds_;
        // When the GCK is fetched, this will process the pending encrypts.
        this.checkForNewGck_(onError);
      }

      return;
    }

    if (now > this.nextCheckForNewGck_) {
      // Need to check for a new GCK.
      this.nextCheckForNewGck_ = now + this.checkForNewGckIntervalMilliseconds_;
      if (!this.isGckRetrievalInProgress_)
        this.checkForNewGck_(onError);
      // Continue below to encrypt with the current key.
    }
  }

  var encryptedContent = encrypt(plainData);
  try {
    onSuccess(encryptedContent);
  } catch (ex) {
    console.log("Error in onSuccess: " + NdnCommon.getErrorWithStackTrace(ex));
  }
};

/**
 * Create a new Content Key (CK) and publish the corresponding CK Data packet.
 * This uses the onError given to the constructor to report errors.
 * @throws Error if this EncryptorV2 uses a group content key.
 */
EncryptorV2.prototype.regenerateCk = function()
{
  if (this.isUsingGck_())
    throw new Error("This EncryptorV2 uses a group content key. Cannot regenerateCk()");

  // TODO: Ensure that the CK Data packet for the old CK is published when the
  // CK is updated before the KEK is fetched.

  this.ckName_ = new Name(this.ckPrefix_);
  this.ckName_.append(EncryptorV2.NAME_COMPONENT_CK);
  // The version is the ID of the CK.
  this.ckName_.appendVersion(new Date().getTime());

  if (LOG > 3) console.log("Generating new CK: " + this.ckName_.toUri());
  this.ckBits_ = Crypto.randomBytes(EncryptorV2.AES_KEY_SIZE);

  // One implication: If the CK is updated before the KEK is fetched, then
  // the KDK for the old CK will not be published.
  if (this.kekData_ == null)
    this.retryFetchingKek_();
  else
    this.makeAndPublishCkData_(function(){}, this.onError_);
};

/**
 * Set the interval for sending an Interest to the access manager to get the
 * name of the latest GCK (and to fetch it if it is new). If you don't call
 * this, then use the default of 1 minute.
 * @param {number} checkForNewGckInterval The interval in milliseconds.
 */
EncryptorV2.prototype.setCheckForNewGckInterval = function(checkForNewGckInterval)
{
  this.checkForNewGckIntervalMilliseconds_ = checkForNewGckInterval;
}

/**
 * Get the number of packets stored in in-memory storage.
 * @return {number} The number of packets.
 */
EncryptorV2.prototype.size = function()
{
  return this.storage_.size();
};

EncryptorV2.PendingEncrypt = function EncryptorV2PendingEncrypt
  (plainData, onSuccess, onError)
{
  this.plainData = plainData;
  this.onSuccess = onSuccess;
  this.onError = onError;
};

EncryptorV2.prototype.retryFetchingKek_ = function()
{
  if (this.isKekRetrievalInProgress_)
    return;

  if (LOG > 3) console.log("Retrying fetching of the KEK");
  this.isKekRetrievalInProgress_ = true;

  var thisEncryptor = this;
  this.fetchKekAndPublishCkData_
    (function() {
       if (LOG > 3) console.log("The KEK was retrieved and published");
       thisEncryptor.isKekRetrievalInProgress_ = false;
     },
     function(errorCode, message) {
       if (LOG > 3) console.log("Failed to retrieve KEK: " + message);
       thisEncryptor.isKekRetrievalInProgress_ = false;
       thisEncryptor.onError_(errorCode, message);
     },
     EncryptorV2.N_RETRIES);
};

/**
 * Create an Interest for <access-prefix>/KEK to retrieve the
 * <access-prefix>/KEK/<key-id> KEK Data packet, and set kekData_.
 * @param {function} onReady When the KEK is retrieved and published, this calls
 * onReady().
 * @param {function} onError On failure, this calls onError(errorCode, message)
 * where errorCode is from EncryptError.ErrorCode, and message is an error
 * string.
 * @param {number} nTriesLeft The number of retries for expressInterest timeouts.
 */
EncryptorV2.prototype.fetchKekAndPublishCkData_ = function
  (onReady, onError, nTriesLeft)
{
  if (LOG > 3) console.log("Fetching KEK: " +
    new Name(this.accessPrefix_).append(EncryptorV2.NAME_COMPONENT_KEK).toUri());

  if (this.kekPendingInterestId_ > 0) {
    onError(EncryptError.ErrorCode.General,
      "fetchKekAndPublishCkData: There is already a kekPendingInterestId_");
    return;
  }

  var thisEncryptor = this;
  var onData = function(interest, kekData) {
    thisEncryptor.kekPendingInterestId_ = 0;

    // Validate the Data signature.
    thisEncryptor.validator_.validate
      (kekData,
       function(d) {
         thisEncryptor.kekData_ = kekData;
         thisEncryptor.makeAndPublishCkData_(onReady, onError);
       },
       function(d, error) {
         onError(EncryptError.ErrorCode.CkRetrievalFailure,
           "Validate KEK Data failure: " + error.toString());
       });
  };

  var onTimeout = function(interest) {
    thisEncryptor.kekPendingInterestId_ = 0;
    if (nTriesLeft > 1)
      thisEncryptor.fetchKekAndPublishCkData_(onReady, onError, nTriesLeft - 1);
    else {
      onError(EncryptError.ErrorCode.KekRetrievalTimeout,
        "Retrieval of KEK [" + interest.getName().toUri() + "] timed out");
      if (LOG > 3) console.log("Scheduling retry after all timeouts");
      setTimeout
        (function() { thisEncryptor.retryFetchingKek_(); },
         EncryptorV2.RETRY_DELAY_KEK_RETRIEVAL_MS);
    }
  };

  var onNetworkNack = function(interest, networkNack) {
    thisEncryptor.kekPendingInterestId_ = 0;
    if (nTriesLeft > 1) {
      setTimeout
        (function() {
           thisEncryptor.fetchKekAndPublishCkData_(onReady, onError, nTriesLeft - 1);
         },
         EncryptorV2.RETRY_DELAY_AFTER_NACK_MS);
    }
    else {
      onError(EncryptError.ErrorCode.KekRetrievalFailure,
        "Retrieval of KEK [" + interest.getName().toUri() +
        "] failed. Got NACK (" + networkNack.getReason() + ")");
      if (LOG > 3) console.log("Scheduling retry from NACK");
      setTimeout
        (function() { thisEncryptor.retryFetchingKek_(); },
         EncryptorV2.RETRY_DELAY_KEK_RETRIEVAL_MS);
    }
  };

  try {
    this.kekPendingInterestId_ = this.face_.expressInterest
      (new Interest(new Name(this.accessPrefix_).append(EncryptorV2.NAME_COMPONENT_KEK))
         .setMustBeFresh(true)
         .setCanBePrefix(true),
       onData, onTimeout, onNetworkNack);
  } catch (ex) {
    onError(EncryptError.ErrorCode.General, "expressInterest error: " + ex);
  }
};

/**
 * Make a CK Data packet for ckName_ encrypted by the KEK in kekData_ and
 * insert it in the storage_.
 * @param {function} onReady When the CK Data packet is made and published, this
 * calls onReady().
 * @param {function} onError On failure, this calls onError(errorCode, message)
 * where errorCode is from EncryptError.ErrorCode, and message is an error
 * string.
 */
EncryptorV2.prototype.makeAndPublishCkData_ = function(onReady, onError)
{
  try {
    var kek = new PublicKey(this.kekData_.getContent());

    var content = new EncryptedContent();
    // Debug: Use a Promise.
/* See https://github.com/operantnetworks/ndn-direct-ind/issues/12
    var payload = kek.encrypt(this.ckBits_, EncryptAlgorithmType.RsaOaep);
 */
    var payload = kek.encrypt(this.ckBits_, EncryptAlgorithmType.RsaPkcs);
    content.setPayload(payload);

    var ckData = new Data
      (new Name(this.ckName_).append(EncryptorV2.NAME_COMPONENT_ENCRYPTED_BY)
       .append(this.kekData_.getName()));
    ckData.setContent(content.wireEncodeV2());
    // FreshnessPeriod can serve as a soft access control for revoking access.
    ckData.getMetaInfo().setFreshnessPeriod
      (EncryptorV2.DEFAULT_CK_FRESHNESS_PERIOD_MS);
    var thisEncryptor = this;
    this.keyChain_.signPromise(ckData, this.ckDataSigningInfo_)
      .then(function() {
      thisEncryptor.storage_.insert(ckData);

      if (LOG > 3) console.log("Publishing CK data: " + ckData.getName().toUri());
      onReady();
      return SyncPromise.resolve();
    })
    .catch(function(err) {
      onError(EncryptError.ErrorCode.EncryptionFailure,
        "Failed to sign CK data " + ckData.getName().toUri() + ": " + err);
    });
  } catch (ex) {
    onError(EncryptError.ErrorCode.EncryptionFailure,
      "Failed to encrypt generated CK with KEK " + this.kekData_.getName().toUri());
  }
};


/**
 * Send an interest for the gckLatestPrefix_ to get the name of the latest
 * GCK. If it doesn't match gckName_, then call fetchGck().
 * @param {function} onError On failure, this calls onError(errorCode, message)
 * where errorCode is from EncryptError.ErrorCode, and message is an error
 * string.
 */
EncryptorV2.prototype.checkForNewGck_ = function(onError)
{
  if (this.isGckRetrievalInProgress_)
    // Already checking.
    return;
  this.isGckRetrievalInProgress_ = true;

  var thisEncryptor = this;
  var onData = function(ckInterest, gckLatestData) {
    // Validate the Data signature.
    thisEncryptor.validator_.validate
      (gckLatestData,
       function(d) {
         var newGckName = new Name();
         try {
           newGckName.wireDecode(gckLatestData.getContent());
         } catch (ex) {
           thisEncryptor.isGckRetrievalInProgress_ = false;
           onError(EncryptError.ErrorCode.CkRetrievalFailure,
             "Error decoding GCK name in: " + gckLatestData.getName().toUri());
         }

         if (newGckName.equals(thisEncryptor.ckName_)) {
           // The latest is the same name, so do nothing.
           thisEncryptor.isGckRetrievalInProgress_ = false;
           return;
         }

         // Leave isGckRetrievalInProgress_ true.
         thisEncryptor.fetchGck_(newGckName, onError, EncryptorV2.N_RETRIES);
       },
       function(d, error) {
         thisEncryptor.isGckRetrievalInProgress_ = false;
         onError(EncryptError.ErrorCode.CkRetrievalFailure,
           "Validate GCK latest_ Data failure: " + error.toString());
       });
  };

  var onTimeout = function(interest) {
    thisEncryptor.isGckRetrievalInProgress_ = false;
    onError(EncryptError.ErrorCode.CkRetrievalTimeout,
      "Timeout for GCK _latest packet: " + interest.getName().toUri());
  };

  var onNetworkNack = function(interest, networkNack) {
    thisEncryptor.isGckRetrievalInProgress_ = false;
    onError(EncryptError.ErrorCode.CkRetrievalFailure,
      "Network nack for GCK _latest packet: " + interest.getName().toUri() +
      ". Got NACK (" + networkNack.getReason() + ")");
  };

  try {
    this.face_.expressInterest
      (new Interest(this.gckLatestPrefix_).setMustBeFresh(true).setCanBePrefix(true),
       onData, onTimeout, onNetworkNack);
  } catch (ex) {
    thisEncryptor.isGckRetrievalInProgress_ = false;
    onError(EncryptError.ErrorCode.General, "expressInterest error: " + ex);
  }
};

/**
 * Fetch the Data packet <gckName>/ENCRYPTED-BY/<credentials-key> and call
 * decryptGck to decrypt it.
 * @param {Name} gckName The name of the group content key formed from the
 * access prefix, e.g. <access-prefix>/GCK/<gck-id> .
 * @param {function} onError On failure, this calls onError(errorCode, message)
 * where errorCode is from EncryptError.ErrorCode, and message is an error
 * string.
 * @param {number} nTriesLeft If fetching times out, decrement nTriesLeft and
 * try again until it is zero.
 */
EncryptorV2.prototype.fetchGck_ = function(gckName, onError, nTriesLeft)
{
  // This is only called from checkForNewGck, so isGckRetrievalInProgress_ is true.

  // <access-prefix>/GCK/<gck-id>  /ENCRYPTED-BY /<credential-identity>/KEY/<key-id>
  // \                          /                \                                 /
  //  -----------  -------------                  ----------------  ---------------
  //             \/                                               \/
  //           gckName                                    from configuration

  var encryptedGckName = new Name(gckName);
  encryptedGckName
    .append(EncryptorV2.NAME_COMPONENT_ENCRYPTED_BY)
    .append(this.credentialsKey_.getName());

  if (LOG > 3) console.log("EncryptorV2: Fetching GCK " + encryptedGckName.toUri());

  var thisEncryptor = this;
  var onData = function(ckInterest, ckData) {
    try {
      thisEncryptor.gckPendingInterestId_ = 0;

      // Leave isGckRetrievalInProgress_ true.
      thisEncryptor.decryptGckAndProcessPendingDecrypts_(gckName, ckData, onError);
    } catch (ex) {
      onError(EncryptError.ErrorCode.General,
        "Error in EncryptorV2::fetchGck onData: " + ex);
    }
  };

  var onTimeout = function(interest) {
    thisEncryptor.gckPendingInterestId_ = 0;
    if (nTriesLeft > 1)
      thisEncryptor.fetchGck_(gckName, onError, nTriesLeft - 1);
    else {
      thisEncryptor.isGckRetrievalInProgress_ = false;
      onError(EncryptError.ErrorCode.CkRetrievalTimeout,
        "Retrieval of GCK [" + interest.getName().toUri() + "] timed out");
    }
  };

  var onNetworkNack = function(interest, networkNack) {
    thisEncryptor.gckPendingInterestId_ = 0;
    thisEncryptor.isGckRetrievalInProgress_ = false;
    onError(EncryptError.ErrorCode.CkRetrievalFailure,
      "Retrieval of GCK [" + interest.getName().toUri() +
      "] failed. Got NACK (" + networkNack.getReason() + ")");
  };

  try {
    this.gckPendingInterestId_ = this.face_.expressInterest
      (new Interest(encryptedGckName).setMustBeFresh(true).setCanBePrefix(true),
       onData, onTimeout, onNetworkNack);
  } catch (ex) {
    onError(EncryptError.ErrorCode.General, "expressInterest error: " + ex);
  }
};

/**
 * Decrypt the gckData fetched by fetchGck(), then copy it to ckBits_ and
 * copy gckName to ckName_ . Then process pending decrypts.
 * @param {Name} gckName The Name that fetchGck() used to fetch.
 * @param {Data} gckData The GCK Data packet fetched by fetchGck_().
 * @param {function} onError On failure, this calls onError(errorCode, message)
 * where errorCode is from EncryptError.ErrorCode, and message is an error
 * string.
 */
EncryptorV2.prototype.decryptGckAndProcessPendingDecrypts_ = function
  (gckName, gckData, onError)
{
  // This is only called from fetchGck_, so isGckRetrievalInProgress_ is true.

  if (LOG > 3) console.log("EncryptorV2: Decrypting GCK data " + gckData.getName().toUri());

  var content = new EncryptedContent();
  try {
    content.wireDecodeV2(gckData.getContent());
  } catch (ex) {
    this.isGckRetrievalInProgress_ = false;
    onError(EncryptError.ErrorCode.InvalidEncryptedFormat,
      "Error decrypting EncryptedContent: " + ex);
    return;
  }

  var thisEncryptor = this;
  this.keyChain_.getTpm().decryptPromise
    (content.getPayload().buf(), this.credentialsKey_.getName())
  .then(function(decryptedCkBits) {
    if (decryptedCkBits.isNull()) {
      thisEncryptor.isGckRetrievalInProgress_ = false;
      onError(EncryptError.ErrorCode.TpmKeyNotFound,
        "Could not decrypt secret, " + thisEncryptor.credentialsKey_.getName().toUri() +
        " not found in TPM");
      return SyncPromise.resolve();
    }

    if (decryptedCkBits.size() != thisEncryptor.ckBits_.length) {
      thisEncryptor.isGckRetrievalInProgress_ = false;
      onError(EncryptError.ErrorCode.DecryptionFailure,
        "The decrypted group content key is not the correct size for the encryption algorithm");
      return SyncPromise.resolve();
    }
    thisEncryptor.ckName_ = new Name(gckName);
    decryptedCkBits.buf().copy(thisEncryptor.ckBits_);
    thisEncryptor.isGckRetrievalInProgress_ = false;

    for (var i in thisEncryptor.pendingEncrypts_) {
      var pendingEncrypt = thisEncryptor.pendingEncrypts_[i];
      // TODO: If this calls onError, should we quit?
      var encryptedContent = thisEncryptor.encrypt(pendingEncrypt.plainData);
      try {
        pendingEncrypt.onSuccess(encryptedContent);
      } catch (ex) {
        console.log("Error in onSuccess: " + NdnCommon.getErrorWithStackTrace(ex));
      }
    }

    thisEncryptor.pendingEncrypts = [];
    return SyncPromise.resolve();
  })
  .catch(function(err) {
    this.isGckRetrievalInProgress_ = false;
    onError(EncryptError.ErrorCode.DecryptionFailure,
      "Error decrypting the GCK: " + err);
  });
};

EncryptorV2.prototype.isUsingGck_ = function() { 
  return this.gckLatestPrefix_.size() !== 0;
};

EncryptorV2.NAME_COMPONENT_ENCRYPTED_BY = new Name.Component("ENCRYPTED-BY");
EncryptorV2.NAME_COMPONENT_NAC = new Name.Component("NAC");
EncryptorV2.NAME_COMPONENT_KEK = new Name.Component("KEK");
EncryptorV2.NAME_COMPONENT_KDK = new Name.Component("KDK");
EncryptorV2.NAME_COMPONENT_CK = new Name.Component("CK");
EncryptorV2.NAME_COMPONENT_GCK = new Name.Component("GCK");
EncryptorV2.NAME_COMPONENT_LATEST = new Name.Component("_latest");

EncryptorV2.RETRY_DELAY_AFTER_NACK_MS = 1000.0;
EncryptorV2.RETRY_DELAY_KEK_RETRIEVAL_MS = 60 * 1000.0;

EncryptorV2.AES_KEY_SIZE = 32;
EncryptorV2.AES_IV_SIZE = 16;
EncryptorV2.N_RETRIES = 3;

EncryptorV2.DEFAULT_CK_FRESHNESS_PERIOD_MS = 3600 * 1000.0;

/**
 * Copyright (C) 2020-2021 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: js/encrypt/access-manager-v2.js
 * Original repository: https://github.com/named-data/ndn-js
 *
 * Summary of Changes: Support GCK, async TPM, memberValidator.
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
var RsaKeyParams = require('../security/key-params.js').RsaKeyParams; /** @ignore */
var KeyType = require('../security/security-types').KeyType; /** @ignore */
var SigningInfo = require('../security/signing-info.js').SigningInfo; /** @ignore */
var PublicKey = require('../security/certificate/public-key.js').PublicKey; /** @ignore */
var EncryptedContent = require('./encrypted-content.js').EncryptedContent; /** @ignore */
var EncryptAlgorithmType = require('./algo/encrypt-params.js').EncryptAlgorithmType; /** @ignore */
var InMemoryStorageRetaining = require('../in-memory-storage/in-memory-storage-retaining.js').InMemoryStorageRetaining; /** @ignore */
var NdnCommon = require('../util/ndn-common.js').NdnCommon; /** @ignore */
var EncryptorV2 = require('./encryptor-v2.js').EncryptorV2; /** @ignore */
var Interest = require('../interest.js').Interest; /** @ignore */
var DataValidationState = require('../security/v2/data-validation-state.js').DataValidationState; /** @ignore */
var CertificateRequest = require('../security/v2/certificate-request.js').CertificateRequest; /** @ignore */
var SyncPromise = require('../util/sync-promise.js').SyncPromise; /** @ignore */
var LOG = require('../log.js').Log.LOG;

/**
 * AccessManagerV2 controls the decryption policy by publishing granular
 * per-namespace access policies in the form of key encryption
 * (KEK, plaintext public) and key decryption (KDK, encrypted private key)
 * key pairs. This works with EncryptorV2 and DecryptorV2 using security v2.
 * For the meaning of "KDK", etc. see:
 * https://github.com/named-data/name-based-access-control/blob/new/docs/spec.rst
 * 
 * Create an AccessManagerV2 to serve the KDK or GCK that is encrypted by each
 * group member's public key.
 *
 * If groupContentKeyAlgorithmType is omitted: Create an AccessManagerV2 to
 * serve the NAC public key for other data producers to fetch, and to serve 
 * encrypted versions of the KDK private keys (as safe bags) for authorized
 * consumers to fetch.
 *
 * KEK and KDK naming:
 *
 * [identity]/NAC/[dataset]/KEK            /[key-id]                           (== KEK, public key)
 *
 * [identity]/NAC/[dataset]/KDK/[key-id]   /ENCRYPTED-BY/[user]/KEY/[key-id]   (== KDK, encrypted private key)
 *
 * \_____________  ______________/
 *               \/
 *      registered with NFD
 *
 * If groupContentKeyAlgorithmType is specified, then create an AccessManagerV2
 * to serve the symmetric group content key (GCK) which is encrypted by each
 * group member's public key.
 *
 * [identity]/NAC/[dataset]/GCK/[key-id]   /ENCRYPTED-BY/[user]/KEY/[key-id]   (== GCK, encrypted group content key)
 *
 * \_____________  ___________/
 *               \/
 *      registered with NFD
 *
 * @param {PibIdentity} identity The data owner's namespace identity. (This will
 * be used to sign the KEK and KDK or GCK.)
 * @param {Name} dataset The name of dataset that this manager is controlling.
 * @param {KeyChain} keyChain The KeyChain used to sign Data packets.
 * @param {Face} face The Face for calling registerPrefix that will be used to
 * publish the KEK and KDK Data packets.
 * @param {number} groupContentKeyAlgorithmType (optional) The symmetric 
 * encryption algorithm from EncryptAlgorithmType for which the group content
 * key (GCK) is generated. (For example, EncryptAlgorithmTypeAesCbc.) If null or
 * omitted, do not use a GCK and instead use a KEK and KDK as decrypted above.
 * @throws Error if groupContentKeyAlgorithmType is unrecognized.
 * @constructor
 */
var AccessManagerV2 = function AccessManagerV2
  (identity, dataset, keyChain, face, groupContentKeyAlgorithmType)
{
  this.identity_ = identity;
  this.keyChain_ = keyChain;
  this.face_ = face;

  // storage_ is for the KEK and KDKs (or GCKs).
  this.storage_ = new InMemoryStorageRetaining();
  this.memberValidator_ = null;
  this.onMemberAdded_ = null;
  this.kekRegisteredPrefixId_ = 0;
  this.kdkRegisteredPrefixId_ = 0;

  this.gckAlgorithmType_ = groupContentKeyAlgorithmType;
  this.gckBits_ = Buffer.alloc(0);

  if (this.gckAlgorithmType_ != null)
    this.initializeForGck_(dataset);
  else
    this.initializeForKdk_(dataset);
};

exports.AccessManagerV2 = AccessManagerV2;

AccessManagerV2.prototype.shutdown = function()
{
  this.face_.unsetInterestFilter(this.kekRegisteredPrefixId_);
  this.face_.unsetInterestFilter(this.kdkRegisteredPrefixId_);
};

/**
 * Authorize a member identified by memberCertificate to decrypt data under
 * the policy.
 * @param {CertificateV2} memberCertificate The certificate that identifies the
 * member to authorize.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the published KDK or
 * GCK Data packet, or a promise rejected with an error.
 */
AccessManagerV2.prototype.addMemberPromise = function(memberCertificate, useSync)
{
  if (this.gckAlgorithmType_ != null)
    return this.addMemberForGckPromise_(memberCertificate, useSync);
  else
    return this.addMemberForKdkPromise_(memberCertificate, useSync);
};

/**
 * Authorize a member identified by memberCertificate to decrypt data under
 * the policy.
 * @param {CertificateV2} memberCertificate The certificate that identifies the
 * member to authorize.
 * @param {function} onComplete (optional) This calls
 * onComplete(data) with the published KDK or GCK Data packet. If omitted, the
 * return value is described below. (Some crypto libraries only use a callback,
 * so onComplete is required to use these.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some crypto libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @return {Data} If onComplete is omitted, return the published KDK or GCK Data
 * packet. Otherwise, if onComplete is supplied then return undefined and use
 * onComplete as described above.
 */
AccessManagerV2.prototype.addMember = function(memberCertificate, onComplete, onError)
{
  return SyncPromise.complete(onComplete, onError,
    this.addMemberPromise(memberCertificate, !onComplete));
};

/**
 * Set the Validator which is used to fetch and validate the certificate for the
 * public key in an incoming key request.
 * @param {Validator} memberValidator The Validator to fetch and validate the member
 * certificate. This replaces any previous member Validator.
 * @param {function} (optional) When a new member is added, this calls
 * onMemberAdded(data) with the published Data packet for the new member (the
 * same as the return value from addMember). If onMemberAdded is null or omitted
 * then don't use it.
 */
AccessManagerV2.prototype.setMemberValidator = function
  (memberValidator, onMemberAdded)
{
  this.memberValidator_ = memberValidator;
  this.onMemberAdded_ = onMemberAdded;
};

/**
 * Authorize a member for GCK identified by memberCertificate to decrypt data
 * under the policy.
 * @param {CertificateV2} memberCertificate The certificate that identifies the
 * member to authorize.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the published GCK Data
 * packet.
 */
AccessManagerV2.prototype.addMemberForGckPromise_ = function
  (memberCertificate, useSync)
{
  var memberKey = new PublicKey(memberCertificate.getPublicKey());

  // TODO: Use a promise.
/* See https://github.com/operantnetworks/ndn-direct-ind/issues/12
  var encryptedData = memberKey.encrypt(this.gckBits_, EncryptAlgorithmType.RsaOaep);
 */
  var encryptedData = memberKey.encrypt(this.gckBits_, EncryptAlgorithmType.RsaPkcs);
  var encryptedContent = new EncryptedContent();
  encryptedContent.setPayload(new Blob(encryptedData, false));

  var gckDataName = new Name(this.gckName_);
  gckDataName
    .append(EncryptorV2.NAME_COMPONENT_ENCRYPTED_BY)
    .append(memberCertificate.getKeyName());
  var gckData = new Data(gckDataName);
  gckData.setContent(encryptedContent.wireEncodeV2());
  // FreshnessPeriod can serve as a soft access control for revoking access.
  gckData.getMetaInfo().setFreshnessPeriod
    (AccessManagerV2.DEFAULT_KDK_FRESHNESS_PERIOD_MS);
  var thisManager = this;
  return this.keyChain_.signPromise(gckData, new SigningInfo(this.identity_), useSync)
  .then(function() {
    if (LOG > 3) console.log("Ready to serve GCK Data packet " << gckData.getName().toUri());
    thisManager.storage_.insert(gckData);
    return SyncPromise.resolve(gckData);
  });
};

/**
 * Authorize a member for KDK identified by memberCertificate to decrypt data
 * under the policy.
 * @param {CertificateV2} memberCertificate The certificate that identifies the
 * member to authorize.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the published KDK Data
 * packet.
 */
AccessManagerV2.prototype.addMemberForKdkPromise_ = function
  (memberCertificate, useSync)
{
  var kdkName = new Name(this.nacKey_.getIdentityName());
  kdkName
    .append(EncryptorV2.NAME_COMPONENT_KDK)
    .append(this.nacKey_.getName().get(-1)) // key-id
    .append(EncryptorV2.NAME_COMPONENT_ENCRYPTED_BY)
    .append(memberCertificate.getKeyName());

  var valueLength = 32;
  var value = Crypto.randomBytes(valueLength);
  // To be compatible with OpenSSL which uses a null-terminated string,
  // replace each 0 with 1. And to be compatible with the Java security
  // library which interprets the secret as a char array converted to UTF8,
  // limit each byte to the ASCII range 1 to 127.
  for (var i = 0; i < valueLength; ++i) {
    if (value[i] == 0)
      value[i] = 1;

    value[i] &= 0x7f;
  }

  var kdkSafeBag = this.keyChain_.exportSafeBag
    (this.nacKey_.getDefaultCertificate(), value);

  var memberKey = new PublicKey(memberCertificate.getPublicKey());

  var encryptedContent = new EncryptedContent();
  encryptedContent.setPayload(kdkSafeBag.wireEncode());
  // Debug: Use a Promise.
  encryptedContent.setPayloadKey(memberKey.encrypt
    (value, EncryptAlgorithmType.RsaOaep));

  var kdkData = new Data(kdkName);
  kdkData.setContent(encryptedContent.wireEncodeV2());
  // FreshnessPeriod can serve as a soft access control for revoking access.
  kdkData.getMetaInfo().setFreshnessPeriod
    (AccessManagerV2.DEFAULT_KDK_FRESHNESS_PERIOD_MS);
  var thisManager = this;
  return this.keyChain_.signPromise(kdkData, new SigningInfo(this.identity_), useSync)
  .then(function() {
    thisManager.storage_.insert(kdkData);
    return SyncPromise.resolve(kdkData);
  });
};

/**
 * Generate a new random group content key. You must call setMemberValidator
 * again or call addMember for each member to create the GCK Data packet for the
 * member (which allows you to omit a member's access to the new key if they no
 * longer belong to the group).
 * @throws Error If the constructor was not called with a groupContentKeyAlgorithmType.
 */
AccessManagerV2.prototype.refreshGck = function()
{
  if (this.gckBits_.length == 0)
    throw Error("To use GCK, call the AccessManagerV2 constructor with a groupContentKeyAlgorithmType");

  this.gckName_ = new Name(this.nacIdentityName_);
  this.gckName_.append(EncryptorV2.NAME_COMPONENT_GCK);
  // The version is the ID of the GCK.
  this.gckName_.appendVersion(new Date().getTime());

  if (LOG > 3) console.log("Generating new GCK: " + this.gckName_.toUri());
  this.gckBits_ = Crypto.randomBytes(this.gckBits_.length);

  // The application must add the members again.
  this.storage_.clear();
  this.memberValidator_ = null;
};

/**
 * Get the number of packets stored in in-memory storage.
 * @return {number} The number of packets.
 */
AccessManagerV2.prototype.size = function()
{
  return this.storage_.size();
};

/**
 * Get the sub name after the ENCRRYPTED_BY component. (The result is the
 * member's public key name.
 * @param {Name} name The name with the ENCRRYPTED_BY component.
 * @returns {Name} The sub name after the ENCRRYPTED_BY component, or an empty
 * name if not found.
 */
AccessManagerV2.getEncryptedBy = function(name)
{
  // Search the name backwards for ENCRYPTED_BY.
  for (var i = name.size() - 1; i >= 0; --i) {
    if (name.get(i).equals(EncryptorV2.NAME_COMPONENT_ENCRYPTED_BY))
      return name.getSubName(i + 1);
  }

  // Not found.
  return new Name();
};

AccessManagerV2.prototype.initializeForGck_ = function(dataset)
{
  // The NAC identity is: <identity>/NAC/<dataset>
  this.nacIdentityName_ = new Name(this.identity_.getName())
    .append(EncryptorV2.NAME_COMPONENT_NAC).append(dataset);

  if (this.gckAlgorithmType_ == EncryptAlgorithmType.AesCbc)
    this.gckBits_ = Buffer.alloc(EncryptorV2.AES_KEY_SIZE);
  else
    throw new Error("AccessManagerV2: Unsupported content key algorithm type");

  this.gckLatestPrefix_ = new Name(this.nacIdentityName_)
    .append(EncryptorV2.NAME_COMPONENT_GCK)
    .append(EncryptorV2.NAME_COMPONENT_LATEST);

  this.refreshGck();

  var thisManager = this;
  var onInterest = function(prefix, interest, face, interestFilterId, filter) {
    if (thisManager.gckLatestPrefix_.isPrefixOf(interest.getName())) {
      thisManager.publishGckLatestData_(face);
      return;
    }

    // Serve from storage.
    var data = thisManager.storage_.find(interest);
    if (data != null) {
      if (LOG > 3) console.log
        ("Serving " + data.getName().toUri() + " from InMemoryStorage");
      try {
        face.putData(data);
      } catch (ex) {
        console.log("AccessManagerV2: Error in Face.putData: " +
                    NdnCommon.getErrorWithStackTrace(ex));
      }
    }
    else if (thisManager.memberValidator_ != null)
      // This will log an error if can't find.
      thisManager.fetchAndAddmember_(interest, face);
    else {
      if (LOG > 3) console.log
        ("Didn't find data for " + interest.getName().toUri());
      // TODO: Send NACK?
    }
  };

  var onRegisterFailed = function(prefix) {
    if (LOG > 0) console.log("AccessManagerV2: Failed to register prefix " + prefix.toUri());
  };

  var gckPrefix = new Name(this.nacIdentityName_)
    .append(EncryptorV2.NAME_COMPONENT_GCK);
  this.kdkRegisteredPrefixId_ = this.face_.registerPrefix
    (gckPrefix, onInterest, onRegisterFailed);
};

/**
 * Use memberValidator_.getFetcher() to fetch and validate the certificate for
 * the member's public key named in the interest. Then call addMember and put
 * the resulting Data packet to the face. As usual, addMember adds the Data
 * packet to storage_ so that it can be returned if requested again. If
 * onMemberAdded_ is not null, call onMemberAdded_(data) with the published Data
 * packet.
 * @param {Interest} interest The incoming Interest where the name has the member's
 * public key name following the ENCRYPTED_BY component.
 * @param {Face} face When the response Data packet has been created, call
 * face.putData().
 */
AccessManagerV2.prototype.fetchAndAddmember_ = function(interest, face)
{
  var memberKeyName = AccessManagerV2.getEncryptedBy(interest.getName());
  if (memberKeyName.size() <= 0) {
    if (LOG > 3) console.log
      ("AccessManagerV2: Can't find ENCRYPTED_BY in " + interest.getName().toUri());
    return;
  }

  // In the ValidationState, we only need the failure callback.
  var state = new DataValidationState
    (null, function(d) {}, function(d, error) {
      console.log("AccessManagerV2: Failed to fetch member certificate: " +
        error.toString() + ": onInterest: " + interest.getName().toUri());
    });
  var thisManager = this;
  // Fetch the member certificate.
  this.memberValidator_.getFetcher().fetch
    (new CertificateRequest(new Interest(memberKeyName)), state,
     function(memberCertificate, s) {
       // Validate the member certificate.
       thisManager.memberValidator_.validate
         (memberCertificate,
          function(d) {
            // Add the member.
            thisManager.addMember(memberCertificate, function(data) {
              if (LOG > 3) console.log("Serving " + data.getName().toUri());
              try {
                face.putData(data);
              } catch (ex) {
                console.log("AccessManagerV2: Error in Face.putData: " +
                            NdnCommon.getErrorWithStackTrace(ex));
              }

              if (thisManager.onMemberAdded_ != null) {
                try {
                  thisManager.onMemberAdded_(data);
                } catch (ex) {
                  console.log("AccessManagerV2: Error in onMemberAdded: " +
                              NdnCommon.getErrorWithStackTrace(ex));
                }
              }
            });
          },
          function(d, error) {
            if (LOG > 3) console.log
              ("AccessManagerV2: Validate member certificate failure: " +
               error.toString() + ": " + d.getName().toUri());
          });
     });
};

AccessManagerV2.prototype.initializeForKdk_ = function(dataset)
{
  // The NAC identity is: <identity>/NAC/<dataset>
  this.nacIdentityName_ = new Name(this.identity_.getName())
    .append(EncryptorV2.NAME_COMPONENT_NAC).append(dataset);
  // Generate the NAC key.
  // TODO: Use a Promise.
  var nacIdentity = this.keyChain_.createIdentityV2
    (this.nacIdentityName_, new RsaKeyParams());
  this.nacKey_ = nacIdentity.getDefaultKey();
  if (this.nacKey_.getKeyType() != KeyType.RSA) {
    if (LOG > 3) console.log
      ("Cannot re-use existing KEK/KDK pair, as it is not an RSA key, regenerating");
    this.nacKey_ = this.keyChain_.createKey(nacIdentity, new RsaKeyParams());
  }
  var nacKeyId = this.nacKey_.getName().get(-1);

  var kekPrefix = new Name(this.nacKey_.getIdentityName())
    .append(EncryptorV2.NAME_COMPONENT_KEK);

  var kekData = new Data(this.nacKey_.getDefaultCertificate());
  kekData.setName(new Name(kekPrefix).append(nacKeyId));
  kekData.getMetaInfo().setFreshnessPeriod
    (AccessManagerV2.DEFAULT_KEK_FRESHNESS_PERIOD_MS);
  // TODO: Use a Promise.
  this.keyChain_.sign(kekData, new SigningInfo(this.identity_));
  // A KEK looks like a certificate, but doesn't have a ValidityPeriod.
  this.storage_.insert(kekData);

  var thisManager = this;
  var serveFromStorage = function(prefix, interest, face, interestFilterId, filter) {
    var data = thisManager.storage_.find(interest);
    if (data != null) {
      if (LOG > 3) console.log
        ("Serving " + data.getName().toUri() + " from InMemoryStorage");
      try {
        face.putData(data);
      } catch (ex) {
        console.log("AccessManagerV2: Error in Face.putData: " +
                    NdnCommon.getErrorWithStackTrace(ex));
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

  this.kekRegisteredPrefixId_ = this.face_.registerPrefix
    (kekPrefix, serveFromStorage, onRegisterFailed);

  var kdkPrefix = new Name(this.nacKey_.getIdentityName())
    .append(EncryptorV2.NAME_COMPONENT_KDK).append(nacKeyId);
  this.kdkRegisteredPrefixId_ = this.face_.registerPrefix
    (kdkPrefix, serveFromStorage, onRegisterFailed);
};

/**
 * Make a Data packet with a short freshness period whose name is
 * {gckLatestPrefix_}/{version} and whose content is the encoded gckName_,
 * then put it to the face.
 * @param {Face} face The Face for sending the Data packet.
 */
AccessManagerV2.prototype.publishGckLatestData_ = function(face)
{
  var data = new Data(new Name(this.gckLatestPrefix_)
    .append(Name.Component.fromVersion(new Date().getTime())));
  data.getMetaInfo().setFreshnessPeriod(1000);
  data.setContent(this.gckName_.wireEncode());
  var thisManager = this;
  this.keyChain_.signPromise(data, new SigningInfo(this.identity_))
  .then(function() {
    if (LOG > 3) console.log("Publish GCK _latest Data packet: " +
      data.getName().toUri() + ", contents: " + thisManager.gckName_.toUri());
    face.putData(data);
    return SyncPromise.resolve();
  })
  .catch(function(err) {
    if (LOG > 0) console.log("Error signing GCK _latest Data packet: " + err);
  });
};

AccessManagerV2.DEFAULT_KEK_FRESHNESS_PERIOD_MS = 3600 * 1000.0;
AccessManagerV2.DEFAULT_KDK_FRESHNESS_PERIOD_MS = 3600 * 1000.0;

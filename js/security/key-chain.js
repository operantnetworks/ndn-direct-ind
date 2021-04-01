/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: js/security/key-chain.js
 * Original repository: https://github.com/named-data/ndn-js
 *
 * Summary of Changes: Remove security v1. Use CertificateV2.getPublicKey().
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2014-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx security by Yingdi Yu <yingdi@cs.ucla.edu>.
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
var fs = require('fs'); /** @ignore */
var Crypto = require('../crypto.js'); /** @ignore */
var LOG = require('../log.js').Log.LOG; /** @ignore */
var Name = require('../name.js').Name; /** @ignore */
var Interest = require('../interest.js').Interest; /** @ignore */
var Data = require('../data.js').Data; /** @ignore */
var ContentType = require('../meta-info.js').ContentType; /** @ignore */
var Blob = require('../util/blob.js').Blob; /** @ignore */
var WireFormat = require('../encoding/wire-format.js').WireFormat; /** @ignore */
var SecurityException = require('./security-exception.js').SecurityException; /** @ignore */
var RsaKeyParams = require('./key-params.js').RsaKeyParams; /** @ignore */
var Tpm = require('./tpm/tpm.js').Tpm; /** @ignore */
var TpmBackEndFile = require('./tpm/tpm-back-end-file.js').TpmBackEndFile; /** @ignore */
var TpmBackEndMemory = require('./tpm/tpm-back-end-memory.js').TpmBackEndMemory; /** @ignore */
var SyncPromise = require('../util/sync-promise.js').SyncPromise; /** @ignore */
var CertificateV2 = require('./v2/certificate-v2.js').CertificateV2; /** @ignore */
var SigningInfo = require('./signing-info.js').SigningInfo; /** @ignore */
var Sha256WithRsaSignature = require('../sha256-with-rsa-signature.js').Sha256WithRsaSignature; /** @ignore */
var Sha256WithEcdsaSignature = require('../sha256-with-ecdsa-signature.js').Sha256WithEcdsaSignature; /** @ignore */
var DigestSha256Signature = require('../digest-sha256-signature.js').DigestSha256Signature; /** @ignore */
var HmacWithSha256Signature = require('../hmac-with-sha256-signature.js').HmacWithSha256Signature; /** @ignore */
var KeyLocator = require('../key-locator.js').KeyLocator; /** @ignore */
var KeyLocatorType = require('../key-locator.js').KeyLocatorType; /** @ignore */
var DigestAlgorithm = require('./security-types.js').DigestAlgorithm; /** @ignore */
var KeyType = require('./security-types.js').KeyType; /** @ignore */
var ValidityPeriod = require('./validity-period.js').ValidityPeriod; /** @ignore */
var SafeBag = require('./safe-bag.js').SafeBag; /** @ignore */
var VerificationHelpers = require('./verification-helpers.js').VerificationHelpers; /** @ignore */
var PublicKey = require('./certificate/public-key.js').PublicKey;

/**
 * KeyChain is the main class of the security library.
 * 
 * The KeyChain class provides a set of interfaces to the security library such
 * as identity management and packet signing.
 * Note: This class is an experimental feature. See the API docs for more detail at
 * http://named-data.net/doc/ndn-ccl-api/key-chain.html .
 *
 * There are three forms to create a KeyChain:
 * KeyChain(pibLocator, tpmLocator, allowReset = false) - Create a KeyChain to
 * use the PIB and TPM defined by the given locators, which creates a security
 * v2 KeyChain that uses CertificateV2, Pib, Tpm and Validator.
 * KeyChain(pibImpl, tpmBackEnd) - Create a security v2 KeyChain with
 * explicitly-created PIB and TPM objects.
 * Finally, the default constructor KeyChain() creates a KeyChain with the
 * default PIB and TPM, which are platform-dependent and can be overridden
 * system-wide or individually by the user.
 * @param {string} pibLocator The PIB locator, e.g., "pib-sqlite3:/example/dir".
 * @param {string} tpmLocator The TPM locator, e.g., "tpm-memory:".
 * @param {boolean} allowReset (optional) If True, the PIB will be reset when
 * the supplied tpmLocator mismatches the one in the PIB. If omitted, don't
 * allow reset.
 * @param {PibImpl} pibImpl An explicitly-created PIB object of a subclass of
 * PibImpl.
 * @param {TpmBackEnd} tpmBackEnd: An explicitly-created TPM object of a
 * subclass of TpmBackEnd.
 * @throws KeyChain.LocatorMismatchError if the supplied TPM locator does not
 * match the locator stored in the PIB.
 * @constructor
 */
var KeyChain = function KeyChain(arg1, arg2, arg3)
{
  this.pib_ = null;
  this.tpm_ = null;

  if (arg1 == undefined) {
    // The default constructor.
    if (!ConfigFile)
      // Assume we are in the browser.
      throw new SecurityException(new Error
        ("KeyChain: The default KeyChain constructor is not supported in the browser"));

    // Set the security v2 locators to default empty strings.
    arg1 = "";
    arg2 = "";
  }

  if (typeof arg1 === 'string') {
    var pibLocator = arg1;
    var tpmLocator = arg2;
    var allowReset = arg3;
    if (allowReset == undefined)
      allowReset = false;

    // PIB locator.
    var pibScheme = [null];
    var pibLocation = [null];
    KeyChain.parseAndCheckPibLocator_(pibLocator, pibScheme, pibLocation);
    var canonicalPibLocator = pibScheme[0] + ":" + pibLocation[0];

    // Create the PIB and TPM, where Pib.initializePromise_ will complete the
    // initialization the first time it is called in an asynchronous context. We
    // can't do it here because this constructor cannot perform async operations.
    this.pib_ = KeyChain.createPib_(canonicalPibLocator);
    this.tpm_ = new Tpm("", "", null);
    this.pib_.initializeTpm_ = this.tpm_;
    this.pib_.initializePibLocator_ = pibLocator;
    this.pib_.initializeTpmLocator_ = tpmLocator;
    this.pib_.initializeAllowReset_ = allowReset;
    this.tpm_.initializePib_ = this.pib_;
  }
  else if (arg1 instanceof PibImpl) {
    var pibImpl = arg1;
    var tpmBackEnd = arg2;

    this.pib_ = new Pib("", "", pibImpl);
    this.tpm_ = new Tpm("", "", tpmBackEnd);
  }
};

exports.KeyChain = KeyChain;

/**
 * Create a KeyChain.Error which represents an error in KeyChain processing.
 * Call with: throw new KeyChain.Error(new Error("message")).
 * @constructor
 * @param {Error} error The exception created with new Error.
 */
KeyChain.Error = function KeyChainError(error)
{
  if (error) {
    error.__proto__ = KeyChain.Error.prototype;
    return error;
  }
};

KeyChain.Error.prototype = new Error();
KeyChain.Error.prototype.name = "KeyChainError";

/**
 * @return {Pib}
 */
KeyChain.prototype.getPib = function() { return this.pib_; };

/**
 * @return {Tpm}
 */
KeyChain.prototype.getTpm = function() { return this.tpm_; };

// Identity management

/**
 * Create a security V2 identity for identityName. This method will check if the
 * identity exists in PIB and whether the identity has a default key and default
 * certificate. If the identity does not exist, this method will create the
 * identity in PIB. If the identity's default key does not exist, this method
 * will create a key pair and set it as the identity's default key. If the key's
 * default certificate is missing, this method will create a self-signed
 * certificate for the key. If identityName did not exist and no default
 * identity was selected before, the created identity will be set as the default
 * identity.
 * @param {Name} identityName The name of the identity.
 * @param {KeyParams} params (optional) The key parameters if a key needs to be
 * generated for the identity. If omitted, use getDefaultKeyParams().
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that returns the created PibIdentity
 * instance.
 */
KeyChain.prototype.createIdentityV2Promise = function
  (identityName, params, useSync)
{
  useSync = (typeof params === "boolean") ? params : useSync;
  params = (typeof params === "boolean" || !params) ? undefined : params;

  if (params == undefined)
    params = KeyChain.getDefaultKeyParams();

  var thisKeyChain = this;
  var id;

  return this.pib_.addIdentityPromise_(identityName, useSync)
  .then(function(localId) {
    id = localId;

    return id.getDefaultKeyPromise(useSync)
    .catch(function(err) {
      if (err instanceof Pib.Error)
        return thisKeyChain.createKeyPromise(id, params, useSync);
      else
        return SyncPromise.reject(err);
    });
  })
  .then(function(key) {
    return key.getDefaultCertificatePromise(useSync)
    .catch(function(err) {
      if (err instanceof Pib.Error) {
        if (LOG > 2)
          console.log("No default cert for " + key.getName() +
            ", requesting self-signing")
        return thisKeyChain.selfSignPromise(key, useSync);
      }
      else
        return SyncPromise.reject(err);
    });
  })
  .then(function() {
    return SyncPromise.resolve(id);
  });
};

/**
 * Create a security V2 identity for identityName. This method will check if the
 * identity exists in PIB and whether the identity has a default key and default
 * certificate. If the identity does not exist, this method will create the
 * identity in PIB. If the identity's default key does not exist, this method
 * will create a key pair and set it as the identity's default key. If the key's
 * default certificate is missing, this method will create a self-signed
 * certificate for the key. If identityName did not exist and no default
 * identity was selected before, the created identity will be set as the default
 * identity.
 * @param {Name} identityName The name of the identity.
 * @param {KeyParams} params (optional) The key parameters if a key needs to be
 * generated for the identity. If omitted, use getDefaultKeyParams().
 * @param {function} onComplete (optional) This calls
 * onComplete(identity) with the created PibIdentity instance. If omitted, the
 * return value is described below. (Some database libraries only use a callback,
 * so onComplete is required to use these.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @return {PibIdentity} If onComplete is omitted, return the created
 * PibIdentity instance. Otherwise, if onComplete is supplied then return
 * undefined and use onComplete as described above.
 */
KeyChain.prototype.createIdentityV2 = function
  (identityName, params, onComplete, onError)
{
  onError = (typeof params === "function") ? onComplete : onError;
  onComplete = (typeof params === "function") ? params : onComplete;
  params = (typeof params === "function" || !params) ? undefined : params;

  return SyncPromise.complete(onComplete, onError,
    this.createIdentityV2Promise(identityName, params, !onComplete));
};

/**
 * elete the PibIdentity identity. After this operation, the identity is invalid.
 * @param {PibIdentity} identity The identity to delete.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that fulfills when the operation is
 * complete.
 */
KeyChain.prototype.deleteIdentityPromise = function(identity, useSync)
{
  var thisKeyChain = this;

  var identityName = identity.getName();
  var keyNames = identity.getKeys_().getKeyNames();

  // Make a recursive function to do the loop.
  function deleteKeys(i) {
    if (i >= keyNames.length)
      // Done.
      return SyncPromise.resolve();

    return thisKeyChain.tpm_.deleteKeyPromise_(keyNames[i], useSync)
    .then(function() {
      // Recurse to the next iteration.
      return deleteKeys(i + 1);
    });
  }

  return deleteKeys(0)
  .then(function() {
    return thisKeyChain.pib_.removeIdentityPromise_(identityName, useSync);
    // TODO: Mark identity as invalid.
  });
};

/**
 * Delete the PibIdentity identity (optionally using onComplete and onError
 * callbacks). After this operation, the identity is invalid.
 * @param {PibIdentity} identity The identity to delete.
 * @param {function} onComplete (optional) This calls onComplete() when the
 * operation is complete. If omitted, do not use it. (Some database libraries
 * only use a callback, so onComplete is required to use these.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 */
KeyChain.prototype.deleteIdentity = function(identity, onComplete, onError)
{
  return SyncPromise.complete(onComplete, onError,
    this.deleteIdentityPromise(identity, !onComplete));
};

/**
 * Set the identity as the default identity.
 * @param {PibIdentity} identity The identity to make the default.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that fulfills when the operation is
 * complete.
 */
KeyChain.prototype.setDefaultIdentityPromise = function(identity, useSync)
{
  return this.pib_.setDefaultIdentityPromise_(identity.getName(), useSync);
};

/**
 * Set the identity as the default identity.
 * @param {PibIdentity} identity The identity to make the default.
 * @param {function} onComplete (optional) This calls onComplete() when the
 * operation is complete. If omitted, do not use it. (Some database libraries
 * only use a callback, so onComplete is required to use these.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 */
KeyChain.prototype.setDefaultIdentity = function(identity, onComplete, onError)
{
  return SyncPromise.complete(onComplete, onError,
    this.setDefaultIdentityPromise(identity, !onComplete));
};

// Key management

/**
 * Create a key for the identity according to params. If the identity had no
 * default key selected, the created key will be set as the default for this
 * identity. This method will also create a self-signed certificate for the
 * created key.
 * @param {PibIdentity} identity A valid PibIdentity object.
 * @param {KeyParams} params (optional) The key parameters if a key needs to be
 * generated for the identity. If omitted, use getDefaultKeyParams().
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that returns the new PibKey.
 */
KeyChain.prototype.createKeyPromise = function(identity, params, useSync)
{
  useSync = (typeof params === "boolean") ? params : useSync;
  params = (typeof params === "boolean" || !params) ? undefined : params;

  if (params == undefined)
    params = KeyChain.getDefaultKeyParams();

  var thisKeyChain = this;
  var key, keyName;

  // Create the key in the TPM.
  return this.tpm_.createKeyPromise_(identity.getName(), params, useSync)
  .then(function(localKeyName) {
    keyName = localKeyName;

    // Set up the key info in the PIB.
    return thisKeyChain.tpm_.getPublicKeyPromise(keyName, useSync);
  })
  .then(function(publicKey) {
    return identity.addKeyPromise_(publicKey.buf(), keyName, useSync);
  })
  .then(function(localKey) {
    key = localKey;

    if (LOG > 2)
      console.log
        ("Requesting self-signing for newly created key " + key.getName().toUri());
    return thisKeyChain.selfSignPromise(key, useSync);
  })
  .then(function() {
    return SyncPromise.resolve(key);
  });
};

/**
 * Create a key for the identity according to params. If the identity had no
 * default key selected, the created key will be set as the default for this
 * identity. This method will also create a self-signed certificate for the
 * created key.
 * @param {PibIdentity} identity A valid PibIdentity object.
 * @param {KeyParams} params (optional) The key parameters if a key needs to be
 * generated for the identity. If omitted, use getDefaultKeyParams().
 * @param {function} onComplete (optional) This calls onComplete(key) with the
 * new PibKey. If omitted, the return value is described below. (Some database
 * libraries only use a callback, so onComplete is required to use these.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @return {PibKey} If onComplete is omitted, return the new PibKey. Otherwise,
 * if onComplete is supplied then return undefined and use onComplete as
 * described above.
 */
KeyChain.prototype.createKey = function(identity, params, onComplete, onError)
{
  onError = (typeof params === "function") ? onComplete : onError;
  onComplete = (typeof params === "function") ? params : onComplete;
  params = (typeof params === "function" || !params) ? undefined : params;

  return SyncPromise.complete(onComplete, onError,
    this.createKeyPromise(identity, params, !onComplete));
};

/**
 * Delete the given key of the given identity. The key becomes invalid.
 * @param {PibIdentity} identity A valid PibIdentity object.
 * @param {PibKey} key The key to delete.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that fulfills when the operation is
 * complete, or a promise rejected with Error if the key does not belong to the
 * identity.
 */
KeyChain.prototype.deleteKeyPromise = function(identity, key, useSync)
{
  var keyName = key.getName();
  if (!identity.getName().equals(key.getIdentityName()))
    return SyncPromise.reject(new Error
      ("Identity `" + identity.getName().toUri() + "` does not match key `" +
       keyName.toUri() + "`"));

  var thisKeyChain = this;

  return identity.removeKeyPromise_(keyName, useSync)
  .then(function() {
    return thisKeyChain.tpm_.deleteKeyPromise_(keyName, useSync);
  });
};

/**
 * Delete the given key of the given identity. The key becomes invalid.
 * @param {PibIdentity} identity A valid PibIdentity object.
 * @param {PibKey} key The key to delete.
 * @param {function} onComplete (optional) This calls onComplete() when the
 * operation is complete. If omitted, do not use it. (Some database libraries
 * only use a callback, so onComplete is required to use these.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @throws Error if the key does not belong to the identity. However, if
 * onComplete and onError are defined, then if there is an exception return
 * undefined and call onError(exception).
 */
KeyChain.prototype.deleteKey = function(identity, key, onComplete, onError)
{
  return SyncPromise.complete(onComplete, onError,
    this.deleteKeyPromise(identity, key, !onComplete));
};

/**
 * Set the key as the default key of identity.
 * @param {type} identity A valid PibIdentity object.
 * @param {type} key The key to become the default.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that fulfills when the operation is
 * complete, or a promise rejected with Error if the key does not belong to the
 * identity.
 */
KeyChain.prototype.setDefaultKeyPromise = function(identity, key, useSync)
{
  if (!identity.getName().equals(key.getIdentityName()))
    return SyncPromise.reject(new Error
      ("Identity `" + identity.getName().toUri() + "` does not match key `" +
       key.getName().toUri() + "`"));

  return identity.setDefaultKeyPromise_(key.getName(), useSync);
};

/**
 * Set the key as the default key of identity.
 * @param {type} identity A valid PibIdentity object.
 * @param {type} key The key to become the default.
 * @param {function} onComplete (optional) This calls onComplete() when the
 * operation is complete. If omitted, do not use it. (Some database libraries
 * only use a callback, so onComplete is required to use these.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @throws Error if the key does not belong to the identity. However, if
 * onComplete and onError are defined, then if there is an exception return
 * undefined and call onError(exception).
 */
KeyChain.prototype.setDefaultKey = function(identity, key, onComplete, onError)
{
  return SyncPromise.complete(onComplete, onError,
    this.setDefaultKeyPromise(identity, key, !onComplete));
};

// Certificate management

/**
 * Add a certificate for the key. If the key had no default certificate
 * selected, the added certificate will be set as the default certificate for
 * this key.
 * @param {PibKey} key A valid PibKey object.
 * @param {CertificateV2} certificate The certificate to add. This copies the
 * object.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that fulfills when the operation is
 * complete, or a promise rejected with Error if the key does not match the
 * certificate.
 */
KeyChain.prototype.addCertificatePromise = function(key, certificate, useSync)
{
  if (!key.getName().equals(certificate.getKeyName()) ||
      !certificate.getPublicKey().equals(key.getPublicKey()))
    return SyncPromise.reject(new Error
      ("Key `" + key.getName().toUri() + "` does not match certificate `" +
       certificate.getKeyName().toUri() + "`"));

  return key.addCertificatePromise_(certificate, useSync);
};

/**
 * Add a certificate for the key. If the key had no default certificate
 * selected, the added certificate will be set as the default certificate for
 * this key.
 * @param {PibKey} key A valid PibKey object.
 * @param {CertificateV2} certificate The certificate to add. This copies the
 * object.
 * @param {function} onComplete (optional) This calls onComplete() when the
 * operation is complete. If omitted, do not use it. (Some database libraries
 * only use a callback, so onComplete is required to use these.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @throws Error if the key does not match the certificate. However, if
 * onComplete and onError are defined, then if there is an exception return
 * undefined and call onError(exception).
 */
KeyChain.prototype.addCertificate = function
  (key, certificate, onComplete, onError)
{
  return SyncPromise.complete(onComplete, onError,
    this.addCertificatePromise(key, certificate, !onComplete));
};

/**
 * Delete the certificate with the given name from the given key. If the
 * certificate does not exist, this does nothing.
 * @param {PibKey} key A valid PibKey object.
 * @param {Name} certificateName The name of the certificate to delete.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that fulfills when the operation is
 * complete, or a promise rejected with Error if certificateName does not follow
 * certificate naming conventions.
 */
KeyChain.prototype.deleteCertificatePromise = function
  (key, certificateName, useSync)
{
  if (!CertificateV2.isValidName(certificateName))
    return SyncPromise.reject(new Error
      ("Wrong certificate name `" + certificateName.toUri() + "`"));

  return key.removeCertificatePromise_(certificateName, useSync);
};

/**
 * Delete the certificate with the given name from the given key. If the
 * certificate does not exist, this does nothing.
 * @param {PibKey} key A valid PibKey object.
 * @param {Name} certificateName The name of the certificate to delete.
 * @param {function} onComplete (optional) This calls onComplete() when the
 * operation is complete. If omitted, do not use it. (Some database libraries
 * only use a callback, so onComplete is required to use these.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @throws Error if certificateName does not follow certificate naming
 * conventions. However, if onComplete and onError are defined, then if there is
 * an exception return undefined and call onError(exception).
 */
KeyChain.prototype.deleteCertificate = function
  (key, certificateName, onComplete, onError)
{
  return SyncPromise.complete(onComplete, onError,
    this.deleteCertificatePromise(key, certificateName, !onComplete));
};

/**
 * Set the certificate as the default certificate of the key. The certificate
 * will be added to the key, potentially overriding an existing certificate if
 * it has the same name (without considering implicit digest).
 * @param {PibKey} key A valid PibKey object.
 * @param {CertificateV2} certificate The certificate to become the default.
 * This copies the object.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that fulfills when the operation is
 * complete.
 */
KeyChain.prototype.setDefaultCertificatePromise = function
  (key, certificate, useSync)
{
  // This replaces the certificate it it exists.
  return this.addCertificatePromise(key, certificate, useSync)
  .then(function() {
    return key.setDefaultCertificatePromise_(certificate.getName(), useSync);
  });
};

/**
 * Set the certificate as the default certificate of the key. The certificate
 * will be added to the key, potentially overriding an existing certificate if
 * it has the same name (without considering implicit digest).
 * @param {PibKey} key A valid PibKey object.
 * @param {CertificateV2} certificate The certificate to become the default.
 * This copies the object.
 * @param {function} onComplete (optional) This calls onComplete() when the
 * operation is complete. If omitted, do not use it. (Some database libraries
 * only use a callback, so onComplete is required to use these.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 */
KeyChain.prototype.setDefaultCertificate = function
  (key, certificate, onComplete, onError)
{
  return SyncPromise.complete(onComplete, onError,
    this.setDefaultCertificatePromise(key, certificate, !onComplete));
};

// Signing

/**
 * Sign the target. If it is a Data or Interest object, set its signature. If it
 * is a Buffer, produce a Signature object.
 * @param {Data|Interest|Buffer} target If this is a Data object, wire encode
 * for signing, replace its Signature object based on the type of key and other
 * info in the SigningInfo params or default identity, and update the
 * wireEncoding. If this is an Interest object, wire encode for signing, append
 * a SignatureInfo to the Interest name, sign the name components and append a
 * final name component with the signature bits. If it is a buffer, sign it and
 * return a Signature object.
 * @param {SigningInfo|Name} paramsOrCertificateName (optional) If a SigningInfo,
 * it is the signing parameters. If a Name, it is the certificate name of the
 * key to use for signing. If omitted, use the PIB to get the default key of the
 * default identity.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the input. If omitted, use WireFormat getDefaultWireFormat().
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that returns the target (if target is
 * Data or Interest), or returns the generated Signature object (if target is a
 * Buffer).
 */
KeyChain.prototype.signPromise = function
  (target, paramsOrCertificateName, wireFormat, useSync)
{
  var arg2 = paramsOrCertificateName;
  var arg3 = wireFormat;
  var arg4 = useSync;
  // arg2,                    arg3,       arg4
  // paramsOrCertificateName, wireFormat, useSync
  // paramsOrCertificateName, wireFormat, null
  // paramsOrCertificateName, useSync,    null
  // paramsOrCertificateName, null,       null
  // wireFormat,              useSync,    null
  // wireFormat,              null,       null
  // useSync,                 null,       null
  // null,                    null,       null
  if (arg2 instanceof SigningInfo || arg2 instanceof Name)
    paramsOrCertificateName = arg2;
  else
    paramsOrCertificateName = undefined;

  if (arg2 instanceof WireFormat)
    wireFormat = arg2;
  else if (arg3 instanceof WireFormat)
    wireFormat = arg3;
  else
    wireFormat = undefined;

  if (typeof arg2 === "boolean")
    useSync = arg2;
  else if (typeof arg3 === "boolean")
    useSync = arg3;
  else if (typeof arg4 === "boolean")
    useSync = arg4;
  else
    useSync = false;

  if (wireFormat == undefined)
    wireFormat = WireFormat.getDefaultWireFormat();

  var thisKeyChain = this;

  return SyncPromise.resolve()
  .then(function() {
    if (paramsOrCertificateName == undefined) {
      // Convert sign(target) into sign(target, paramsOrCertificateName)
      paramsOrCertificateName = KeyChain.defaultSigningInfo_;
      return SyncPromise.resolve();
    }
    else
      return SyncPromise.resolve();
  })
  .then(function() {
    if (paramsOrCertificateName instanceof Name) {
      var certificateName = paramsOrCertificateName;

      // Make and use a SigningInfo for backwards compatibility.
      if (!((target instanceof Interest) || (target instanceof Data)))
        return SyncPromise.reject(new SecurityException(new Error
("sign(buffer, certificateName) is not supported for security v2. Use sign with SigningInfo.")));

      var signingInfo = new SigningInfo();
      signingInfo.setSigningCertificateName(certificateName);
      return thisKeyChain.signPromise(target, signingInfo, wireFormat, useSync)
      .catch(function(err) {
        return SyncPromise.reject(new SecurityException(new Error
          ("Error in sign: " + err)));
      });
    }

    var params = paramsOrCertificateName;

    if (target instanceof Data) {
      var data = target;

      var keyName = [null];
      return thisKeyChain.prepareSignatureInfoPromise_(params, keyName, useSync)
      .then(function(signatureInfo) {
        data.setSignature(signatureInfo);

        // Encode once to get the signed portion.
        var encoding = data.wireEncode(wireFormat);

        return thisKeyChain.signBufferPromise_
          (encoding.signedBuf(), keyName[0], params.getDigestAlgorithm(), useSync);
      })
      .then(function(signatureBytes) {
        data.getSignature().setSignature(signatureBytes);

        // Encode again to include the signature.
        data.wireEncode(wireFormat);
        return SyncPromise.resolve(data);
      });
    }
    else if (target instanceof Interest) {
      var interest = target;
      var signatureInfo;

      var keyName = [null];
      return thisKeyChain.prepareSignatureInfoPromise_(params, keyName, useSync)
      .then(function(localSignatureInfo) {
        signatureInfo = localSignatureInfo;

        // Append the encoded SignatureInfo.
        interest.getName().append(wireFormat.encodeSignatureInfo(signatureInfo));

        // Append an empty signature so that the "signedPortion" is correct.
        interest.getName().append(new Name.Component());
        // Encode once to get the signed portion, and sign.
        var encoding = interest.wireEncode(wireFormat);
        return thisKeyChain.signBufferPromise_
          (encoding.signedBuf(), keyName[0], params.getDigestAlgorithm(), useSync);
      })
      .then(function(signatureBytes) {
        signatureInfo.setSignature(signatureBytes);

        // Remove the empty signature and append the real one.
        interest.setName(interest.getName().getPrefix(-1).append
          (wireFormat.encodeSignatureValue(signatureInfo)));
        return SyncPromise.resolve(interest);
      });
    }
    else {
      var buffer = target;

      var keyName = [null];
      return thisKeyChain.prepareSignatureInfoPromise_(params, keyName, useSync)
      .then(function(signatureInfo) {
        return thisKeyChain.signBufferPromise_
          (buffer, keyName[0], params.getDigestAlgorithm(), useSync);
      });
    }
  });
};

/**
 * Sign the target. If it is a Data or Interest object, set its signature. If it
 * is a Buffer, produce a Signature object.
 * @param {Data|Interest|Buffer} target If this is a Data object, wire encode
 * for signing, replace its Signature object based on the type of key and other
 * info in the SigningInfo params or default identity, and update the
 * wireEncoding. If this is an Interest object, wire encode for signing, append
 * a SignatureInfo to the Interest name, sign the name components and append a
 * final name component with the signature bits. If it is a buffer, sign it and
 * return a Signature object.
 * @param {SigningInfo|Name} paramsOrCertificateName (optional) If a SigningInfo,
 * it is the signing parameters. If a Name, it is the certificate name of the
 * key to use for signing. If omitted, use the PIB to get the default key of the
 * default identity.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the input. If omitted, use WireFormat getDefaultWireFormat().
 * @param {function} onComplete (optional) If target is a Data object, this calls
 * onComplete(data) with the supplied Data object which has been modified to set
 * its signature. If target is an Interest object, this calls
 * onComplete(interest) with the supplied Interest object which has been
 * modified to set its signature. If target is a Buffer, this calls
 * onComplete(signature) where signature is the produced Signature object. If
 * omitted, the return value is described below. (Some crypto libraries only use
 * a callback, so onComplete is required to use these.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @return {Signature} If onComplete is omitted, return the generated Signature
 * object (if target is a Buffer) or the target (if target is Data or Interest).
 * Otherwise, if onComplete is supplied then return undefined and use onComplete as
 * described above.
 */
KeyChain.prototype.sign = function
  (target, paramsOrCertificateName, wireFormat, onComplete, onError)
{
  var arg2 = paramsOrCertificateName;
  var arg3 = wireFormat;
  var arg4 = onComplete;
  var arg5 = onError;
  // arg2,                    arg3,       arg4,       arg5
  // paramsOrCertificateName, wireFormat, onComplete, onError
  // paramsOrCertificateName, wireFormat, null,       null
  // paramsOrCertificateName, onComplete, onError,    null
  // paramsOrCertificateName, null,       null,       null
  // wireFormat,              onComplete, onError,    null
  // wireFormat,              null,       null,       null
  // onComplete,              onError,    null,       null
  // null,                    null,       null,       null
  if (arg2 instanceof SigningInfo || arg2 instanceof Name)
    paramsOrCertificateName = arg2;
  else
    paramsOrCertificateName = null;

  if (arg2 instanceof WireFormat)
    wireFormat = arg2;
  else if (arg3 instanceof WireFormat)
    wireFormat = arg3;
  else
    wireFormat = null;

  if (typeof arg2 === "function") {
    onComplete = arg2;
    onError = arg3;
  }
  else if (typeof arg3 === "function") {
    onComplete = arg3;
    onError = arg4;
  }
  else if (typeof arg4 === "function") {
    onComplete = arg4;
    onError = arg5;
  }
  else {
    onComplete = null;
    onError = null;
  }

  return SyncPromise.complete(onComplete, onError,
    this.signPromise(target, paramsOrCertificateName, wireFormat, !onComplete));
};

/**
 * Generate a self-signed certificate for the public key and add it to the PIB.
 * This creates the certificate name from the key name by appending "self" and a
 * version based on the current time. If no default certificate for the key has
 * been set, then set the certificate as the default for the key.
 * @param {PibKey} key The PibKey with the key name and public key.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the certificate. If omitted, use WireFormat getDefaultWireFormat().
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that returns the new CertificateV2.
 */
KeyChain.prototype.selfSignPromise = function(key, wireFormat, useSync)
{
  var arg2 = wireFormat;
  var arg3 = useSync;
  // arg2,       arg3
  // wireFormat, useSync
  // wireFormat, null
  // useSync,    null

  if (arg2 instanceof WireFormat)
    wireFormat = arg2;
  else
    wireFormat = undefined;

  if (typeof arg2 === "boolean")
    useSync = arg2;
  else if (typeof arg3 === "boolean")
    useSync = arg3;
  else
    useSync = false;

  if (wireFormat == undefined)
    wireFormat = WireFormat.getDefaultWireFormat();

  var certificate = new CertificateV2();

  // Set the name.
  var now = new Date().getTime();
  var certificateName = new Name(key.getName());
  certificateName.append("self").appendVersion(now);
  certificate.setName(certificateName);

  // Set the MetaInfo.
  certificate.getMetaInfo().setType(ContentType.KEY);
  // Set a one-hour freshness period.
  certificate.getMetaInfo().setFreshnessPeriod(3600 * 1000.0);

  // Set the content.
  certificate.setContent(key.getPublicKey());

  // Set the signature-info.
  signingInfo = new SigningInfo(key);
  // Set a 20-year validity period.
  signingInfo.setValidityPeriod
    (new ValidityPeriod(now, now + 20 * 365 * 24 * 3600 * 1000.0));

  return this.signPromise(certificate, signingInfo, wireFormat, useSync)
  .then(function() {
    return key.addCertificatePromise_(certificate, useSync)
    .catch(function(ex) {
      // We don't expect this since we just created the certificate.
      return SyncPromise.reject(new KeyChain.Error(new Error
        ("Error encoding certificate: " + ex)));
    });
  })
  .then(function() {
    return SyncPromise.resolve(certificate);
  });
};

/**
 * Generate a self-signed certificate for the public key and add it to the PIB.
 * This creates the certificate name from the key name by appending "self" and a
 * version based on the current time. If no default certificate for the key has
 * been set, then set the certificate as the default for the key.
 * @param {PibKey} key The PibKey with the key name and public key.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the certificate. If omitted, use WireFormat getDefaultWireFormat().
 * @param {function} onComplete (optional) This calls
 * onComplete(certificate) with the new CertificateV2. If omitted, the return
 * value is described below. (Some crypto libraries only use a callback, so
 * onComplete is required to use these.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @return {CertificateV2} If onComplete is omitted, return the new certificate.
 * Otherwise, if onComplete is supplied then return undefined and use onComplete
 * as described above.
 */
KeyChain.prototype.selfSign = function(key, wireFormat, onComplete, onError)
{
  if (typeof wireFormat === 'function') {
    // wireFormat is omitted, so shift.
    onError = onComplete;
    onComplete = wireFormat;
    wireFormat = undefined;
  }

  if (wireFormat == undefined)
    wireFormat = WireFormat.getDefaultWireFormat();

  return SyncPromise.complete(onComplete, onError,
    this.selfSignPromise(key, wireFormat, !onComplete));
};

// Import and export

/**
 * Export a certificate and its corresponding private key in a SafeBag.
 * @param {CertificateV2} certificate The certificate to export. This gets the
 * key from the TPM using certificate.getKeyName().
 * @param {Buffer} word (optional) The password for encrypting the private
 * key, which should have characters in the range of 1 to 127. If the password
 * is supplied, use it to put a PKCS #8 EncryptedPrivateKeyInfo in the SafeBag.
 * If the password is null, put an unencrypted PKCS #8 PrivateKeyInfo in the
 * SafeBag.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns a SafeBag carrying the
 * certificate and private key, or a promise rejected with KeyChain.Error if
 * certificate.getKeyName() key does not exist, if the password is null and the
 * TPM does not support exporting an unencrypted private key, or for other
 * errors exporting the private key.
 */
KeyChain.prototype.exportSafeBagPromise = function
  (certificate, word, useSync)
{
  if (typeof word === 'boolean') {
    // password is omitted, so shift.
    useSync = word;
    word = undefined;
  }

  var keyName = certificate.getKeyName();
  
  var thisKeyChain = this;
  return SyncPromise.resolve()
  .then(function() {
    return thisKeyChain.tpm_.exportPrivateKeyPromise_(keyName, word, useSync);
  }, function(err) {
    return SyncPromise.reject(new KeyChain.Error(new Error
      ("Failed to export private key `" + keyName.toUri() + "`: " + err)));
  })
  .then(function(encryptedKey) {
    return SyncPromise.resolve(new SafeBag(certificate, encryptedKey));
  });
};

/**
 * Export a certificate and its corresponding private key in a SafeBag.
 * @param {CertificateV2} certificate The certificate to export. This gets the
 * key from the TPM using certificate.getKeyName().
 * @param {Buffer} password (optional) The password for encrypting the private
 * key, which should have characters in the range of 1 to 127. If the password
 * is supplied, use it to put a PKCS #8 EncryptedPrivateKeyInfo in the SafeBag.
 * If the password is null, put an unencrypted PKCS #8 PrivateKeyInfo in the
 * SafeBag.
 * @param {function} onComplete (optional) This calls onComplete(safeBag) with a
 * SafeBag carrying the certificate and private key. If omitted, the return
 * value is described below. (Some crypto libraries only use a callback, so
 * onComplete is required to use these.)
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some crypto libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @return {SafeBag} If onComplete is omitted, return a SafeBag carrying the
 * certificate and private key. Otherwise, if onComplete is supplied then return
 * undefined and use onComplete as described above.
 */
KeyChain.prototype.exportSafeBag = function
  (certificate, password, onComplete, onError)
{
  onError = (typeof password === "function") ? onComplete : onError;
  onComplete = (typeof password === "function") ? password : onComplete;
  password = (typeof password === "function") ? null : password;

  return SyncPromise.complete(onComplete, onError,
    this.exportSafeBagPromise(certificate, password, !onComplete));
};

/**
 * Import a certificate and its corresponding private key encapsulated in a
 * SafeBag. If the certificate and key are imported properly, the default
 * setting will be updated as if a new key and certificate is added into this
 * KeyChain.
 * @param {SafeBag} safeBag The SafeBag containing the certificate and private
 * key. This copies the values from the SafeBag.
 * @param {Buffer} word (optional) The password for decrypting the private
 * key, which should have characters in the range of 1 to 127. If the password
 * is supplied, use it to decrypt the PKCS #8 EncryptedPrivateKeyInfo. If the
 * password is omitted or null, import an unencrypted PKCS #8 PrivateKeyInfo.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when finished.
 */
KeyChain.prototype.importSafeBagPromise = function(safeBag, word, useSync)
{
  if (typeof word === 'boolean') {
    // password is omitted, so shift.
    useSync = word;
    word = undefined;
  }

  var certificate;
  try {
    certificate = new CertificateV2(safeBag.getCertificate());
  } catch (ex) {
    return SyncPromise.reject(new Error("Error reading CertificateV2: " + ex));
  }
  var identity = certificate.getIdentity();
  var keyName = certificate.getKeyName();
  var publicKeyBits = certificate.getPublicKey();
  var content = new Blob([0x01, 0x02, 0x03, 0x04]);
  var signatureBits;
  var thisKeyChain = this;

  return SyncPromise.resolve()
  .then(function() {
    return thisKeyChain.tpm_.hasKeyPromise(keyName, useSync);
  })
  .then(function(hasKey) {
    if (hasKey)
      return SyncPromise.reject(new KeyChain.Error(new Error
        ("Private key `" + keyName.toUri() + "` already exists")));

    return thisKeyChain.pib_.getIdentityPromise(identity, useSync)
    .then(function(existingId) {
      return existingId.getKeyPromise(keyName, useSync);
    })
    .then(function() {
      return SyncPromise.reject(new KeyChain.Error(new Error
        ("Public key `" + keyName.toUri() + "` already exists")));
    }, function(err) {
      // Either the identity or the key doesn't exist, so OK to import.
      return SyncPromise.resolve();
    });
  })
  .then(function() {
    return thisKeyChain.tpm_.importPrivateKeyPromise_
      (keyName, safeBag.getPrivateKeyBag().buf(), word, useSync)
    .catch(function(err) {
      return SyncPromise.reject(new KeyChain.Error(new Error
        ("Failed to import private key `" + keyName.toUri() + "`: " + err)));
    });
  })
  .then(function() {
    // Check the consistency of the private key and certificate.
    return thisKeyChain.tpm_.signPromise
      (content.buf(), keyName, DigestAlgorithm.SHA256, useSync)
    .then(function(localSignatureBits) {
      signatureBits = localSignatureBits;
      return SyncPromise.resolve();
    }, function(err) {
      return thisKeyChain.tpm_.deleteKeyPromise_(keyName, useSync)
      .then(function() {
        return SyncPromise.reject(new KeyChain.Error(new Error
          ("Invalid private key `" + keyName.toUri() + "`")));
      });
    });
  })
  .then(function() {
    var publicKey;
    try {
      publicKey = new PublicKey(publicKeyBits);
    } catch (ex) {
      // Promote to KeyChain.Error.
      return thisKeyChain.tpm_.deleteKeyPromise_(keyName, useSync)
      .then(function() {
        return SyncPromise.reject(new KeyChain.Error(new Error
          ("Error decoding public key " + ex)));
      });
    }

    return VerificationHelpers.verifySignaturePromise
      (content, signatureBits, publicKey, useSync);
  })
  .then(function(isVerified) {
    if (!isVerified) {
      return thisKeyChain.tpm_.deleteKeyPromise_(keyName, useSync)
      .then(function() {
        return SyncPromise.reject(new KeyChain.Error(new Error
          ("Certificate `" + certificate.getName().toUri() +
           "` and private key `" + keyName.toUri() + "` do not match")));
      });
    }

    // The consistency is verified. Add to the PIB.
    return thisKeyChain.pib_.addIdentityPromise_(identity, useSync);
  })
  .then(function(id) {
    return id.addKeyPromise_(certificate.getPublicKey().buf(), keyName, useSync);
  })
  .then(function(key) {
    return key.addCertificatePromise_(certificate, useSync);
  });
};

/**
 * Import a certificate and its corresponding private key encapsulated in a
 * SafeBag. If the certificate and key are imported properly, the default
 * setting will be updated as if a new key and certificate is added into this
 * KeyChain.
 * @param {SafeBag} safeBag The SafeBag containing the certificate and private
 * key. This copies the values from the SafeBag.
 * @param {Buffer} password (optional) The password for decrypting the private
 * key, which should have characters in the range of 1 to 127. If the password
 * is supplied, use it to decrypt the PKCS #8 EncryptedPrivateKeyInfo. If the
 * password is omitted or null, import an unencrypted PKCS #8 PrivateKeyInfo.
 * @param {function} onComplete (optional) This calls onComplete() when finished.
 * If omitted, just return when finished. (Some crypto libraries only use a
 * callback, so onComplete is required to use these.)
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
 */
KeyChain.prototype.importSafeBag = function
  (safeBag, password, onComplete, onError)
{
  onError = (typeof password === "function") ? onComplete : onError;
  onComplete = (typeof password === "function") ? password : onComplete;
  password = (typeof password === "function") ? null : password;

  return SyncPromise.complete(onComplete, onError,
    this.importSafeBagPromise(safeBag, password, !onComplete));
};

// PIB & TPM backend registry

/**
 * Add to the PIB factories map where scheme is the key and makePibImpl is the
 * value. If your application has its own PIB implementations, this must be
 * called before creating a KeyChain instance which uses your PIB scheme.
 * @param {string} scheme The PIB scheme.
 * @param {function} makePibImpl A callback which takes the PIB location and
 * returns a new PibImpl instance.
 */
KeyChain.registerPibBackend = function(scheme, makePibImpl)
{
  KeyChain.getPibFactories_()[scheme] = makePibImpl;
};

/**
 * Add to the TPM factories map where scheme is the key and makeTpmBackEnd is
 * the value. If your application has its own TPM implementations, this must be
 * called before creating a KeyChain instance which uses your TPM scheme.
 * @param {string} scheme The TPM scheme.
 * @param {function} makeTpmBackEnd A callback which takes the TPM location and
 * returns a new TpmBackEnd instance.
 */
KeyChain.registerTpmBackend = function(scheme, makeTpmBackEnd)
{
  KeyChain.getTpmFactories_()[scheme] = makeTpmBackEnd;
};

/**
 * Get the default identity.
 * @param {function} onComplete (optional) This calls onComplete(identityName)
 * with name of the default identity. If omitted, the return value is described
 * below. (Some crypto libraries only use a callback, so onComplete is required
 * to use these.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * @return {Name} If onComplete is omitted, return the name of the default
 * identity. Otherwise, if onComplete is supplied then return undefined and use
 * onComplete as described above.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @throws SecurityException if the default identity is not set. However, if
 * onComplete and onError are defined, then if there is an exception return
 * undefined and call onError(exception).
 */
KeyChain.prototype.getDefaultIdentity = function(onComplete, onError)
{
  return this.identityManager_.getDefaultIdentity(onComplete, onError);
};

/**
 * Get the default certificate name of the default identity, which will be used
 * when signing is based on identity and the identity is not specified.
 * @param {function} onComplete (optional) This calls onComplete(certificateName)
 * with name of the default certificate. If omitted, the return value is described
 * below. (Some crypto libraries only use a callback, so onComplete is required
 * to use these.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @return {Name} If onComplete is omitted, return the default certificate name.
 * Otherwise, if onComplete is supplied then return undefined and use onComplete
 * as described above.
 * @throws SecurityException if the default identity is not set or the default
 * key name for the identity is not set or the default certificate name for
 * the key name is not set. However, if onComplete and onError are defined, then
 * if there is an exception return undefined and call onError(exception).
 */
KeyChain.prototype.getDefaultCertificateName = function(onComplete, onError)
{
  return SyncPromise.complete(onComplete, onError,
    this.pib_.getDefaultIdentityPromise(!onComplete)
    .then(function(identity) {
      return identity.getDefaultKeyPromise(!onComplete);
    })
    .then(function(key) {
      return key.getDefaultCertificatePromise(!onComplete);
    })
    .then(function(certificate) {
      return SyncPromise.resolve(certificate.getName());
    }));
};

/**
 * Sign the target using DigestSha256.
 * @param {Data|Interest} target If this is a Data object, wire encode for
 * signing, digest it and set its SignatureInfo to a DigestSha256, updating its
 * signature and wireEncoding. If this is an Interest object, wire encode for
 * signing, append a SignatureInfo for DigestSha256 to the Interest name, digest
 * the name components and append a final name component with the signature bits.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the input. If omitted, use WireFormat getDefaultWireFormat().
 */
KeyChain.prototype.signWithSha256 = function(target, wireFormat)
{
  var signingInfo = SigningInfo();
  signingInfo.setSha256Signing();
  this.sign(target, signingInfo, wireFormat);
};

/**
 * Wire encode the target, compute an HmacWithSha256 and update the object.
 * Note: This method is an experimental feature. The API may change.
 * @param {Data|Interest} target If the target is a Data object (which should
 * already have an HmacWithSha256Signature with a KeyLocator for the key name),
 * then update its signature and wire encoding. If the target is an Interest,
 * then append a SignatureInfo to the Interest name, compute an HmacWithSha256
 * signature for the name components and append a final name component with the
 * signature bits.
 * @param {Blob} key The key for the HmacWithSha256.
 * param {Name} keyName (needed if target is an Interest) The name of the key
 * for the KeyLocator in the SignatureInfo which is added to the Interest name.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the target. If omitted, use WireFormat getDefaultWireFormat().
 */
KeyChain.signWithHmacWithSha256 = function(target, key, keyName, wireFormat)
{
  if (keyName instanceof WireFormat) {
    // The keyName is omitted, so shift arguments.
    wireFormat = keyName;
    keyName = undefined;
  }

  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  if (target instanceof Data) {
    var data = target;
    // Encode once to get the signed portion.
    var encoding = data.wireEncode(wireFormat);

    var signer = Crypto.createHmac('sha256', key.buf());
    signer.update(encoding.signedBuf());
    data.getSignature().setSignature(
      new Blob(signer.digest(), false));
  }
  else if (target instanceof Interest) {
    var interest = target;

    if (keyName == null)
      throw new SecurityException(new Error
        ("signWithHmacWithSha256: keyName is required to sign an Interest"));

    var signature = new HmacWithSha256Signature();
    signature.getKeyLocator().setType(KeyLocatorType.KEYNAME);
    signature.getKeyLocator().setKeyName(keyName);

    // Append the encoded SignatureInfo.
    interest.getName().append(wireFormat.encodeSignatureInfo(signature));
    // Append an empty signature so that the "signedPortion" is correct.
    interest.getName().append(new Name.Component());

    // Encode once to get the signed portion.
    var encoding = interest.wireEncode(wireFormat);

    var signer = Crypto.createHmac('sha256', key.buf());
    signer.update(encoding.signedBuf());
    signature.setSignature(new Blob(signer.digest(), false));

    // Remove the empty signature and append the real one.
    interest.setName(interest.getName().getPrefix(-1).append
      (wireFormat.encodeSignatureValue(signature)));
  }
  else
    throw new SecurityException(new Error
      ("signWithHmacWithSha256: Unrecognized target type"));
};

/**
 * Compute a new HmacWithSha256 for the target and verify it against the
 * signature value.
 * Note: This method is an experimental feature. The API may change.
 * @param {Data} data The Data object to verify.
 * @param {Blob} key The key for the HmacWithSha256.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the input. If omitted, use WireFormat getDefaultWireFormat().
 * @return {boolean} True if the signature verifies, otherwise false.
 */
KeyChain.verifyDataWithHmacWithSha256 = function(data, key, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  // wireEncode returns the cached encoding if available.
  var encoding = data.wireEncode(wireFormat);

  var signer = Crypto.createHmac('sha256', key.buf());
  signer.update(encoding.signedBuf());
  var newSignatureBits = new Blob(signer.digest(), false);

  // Use the flexible Blob.equals operator.
  return newSignatureBits.equals(data.getSignature().getSignature());
};

/**
 * Compute a new HmacWithSha256 for all but the final name component and verify
 * it against the signature value in the final name component.
 * Note: This method is an experimental feature. The API may change.
 * @param {Interest} interest The Interest object to verify.
 * @param {Blob} key The key for the HmacWithSha256.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the input. If omitted, use WireFormat getDefaultWireFormat().
 * @return {boolean} True if the signature verifies, otherwise false.
 */
KeyChain.verifyInterestWithHmacWithSha256 = function(interest, key, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  // Decode the last two name components of the signed interest.
  var signature = wireFormat.decodeSignatureInfoAndValue
    (interest.getName().get(-2).getValue().buf(),
     interest.getName().get(-1).getValue().buf());

  // wireEncode returns the cached encoding if available.
  var encoding = interest.wireEncode(wireFormat);

  var signer = Crypto.createHmac('sha256', key.buf());
  signer.update(encoding.signedBuf());
  var newSignatureBits = new Blob(signer.digest(), false);

  // Use the flexible Blob.equals operator.
  return newSignatureBits.equals(signature.getSignature());
};

KeyChain.getDefaultKeyParams = function() { return KeyChain.defaultKeyParams_; };

/**
 * @deprecated Use getDefaultKeyParams().
 */
KeyChain.DEFAULT_KEY_PARAMS = new RsaKeyParams();

// Private security v2 methods

/**
 * Get the PIB factories map. On the first call, this initializes the map with
 * factories for standard PibImpl implementations.
 * @return {object} A map where the key is the scheme string and the value is a
 * function makePibImpl(location) which takes a string location and returns a
 * new PibImpl object.
 */
KeyChain.getPibFactories_ = function()
{
  if (KeyChain.pibFactories_ == null) {
    KeyChain.pibFactories_ = {};

    // Add the standard factories.
    if (PibSqlite3)
      // PibSqlite3 is defined for Node.js .
      KeyChain.pibFactories_[PibSqlite3.getScheme()] =
        function(location) { return new PibSqlite3(location); };
    KeyChain.pibFactories_[PibMemory.getScheme()] =
      function(location) { return new PibMemory(); };
  }

  return KeyChain.pibFactories_;
};

/**
 * Get the TPM factories map. On the first call, this initializes the map with
 * factories for standard TpmBackEnd implementations.
 * @return {object} A map where the key is the scheme string and the value is a
 * function makeTpmBackEnd(location) which takes a string location and returns a
 * new TpmBackEnd object.
 */
KeyChain.getTpmFactories_ = function()
{
  if (KeyChain.tpmFactories_ == null) {
    KeyChain.tpmFactories_ = {};

    // Add the standard factories.
    if (TpmBackEndFile)
      // TpmBackEndFile is defined for Node.js .
      KeyChain.tpmFactories_[TpmBackEndFile.getScheme()] =
        function(location) { return new TpmBackEndFile(location); };
    KeyChain.tpmFactories_[TpmBackEndMemory.getScheme()] =
      function(location) { return new TpmBackEndMemory(); };
  }

  return KeyChain.tpmFactories_;
};

/**
 * Parse the uri and set the scheme and location.
 * @param {string} uri The URI to parse.
 * @param {Array<string>} scheme Set scheme[0] to the scheme.
 * @param {Array<string>} location Set location[0] to the location.
 */
KeyChain.parseLocatorUri_ = function(uri, scheme, location)
{
  iColon = uri.indexOf(':');
  if (iColon >= 0) {
    scheme[0] = uri.substring(0, iColon);
    location[0] = uri.substring(iColon + 1);
  }
  else {
    scheme[0] = uri;
    location[0] = "";
  }
};

/**
 * Parse the pibLocator and set the pibScheme and pibLocation.
 * @param {string} pibLocator The PIB locator to parse.
 * @param {Array<string>} pibScheme Set pibScheme[0] to the PIB scheme.
 * @param {Array<string>} pibLocation Set pibLocation[0] to the PIB location.
 */
KeyChain.parseAndCheckPibLocator_ = function(pibLocator, pibScheme, pibLocation)
{
  KeyChain.parseLocatorUri_(pibLocator, pibScheme, pibLocation);

  if (pibScheme[0] == "")
    pibScheme[0] = KeyChain.getDefaultPibScheme_();

  if (KeyChain.getPibFactories_()[pibScheme[0]] == undefined)
    throw new KeyChain.Error(new Error
      ("PIB scheme `" + pibScheme[0] + "` is not supported"));
};

/**
 * Parse the tpmLocator and set the tpmScheme and tpmLocation.
 * @param {string} tpmLocator The TPM locator to parse.
 * @param {Array<string>} tpmScheme Set tpmScheme[0] to the TPM scheme.
 * @param {Array<string>} tpmLocation Set tpmLocation[0] to the TPM location.
 */
KeyChain.parseAndCheckTpmLocator_ = function(tpmLocator, tpmScheme, tpmLocation)
{
  KeyChain.parseLocatorUri_(tpmLocator, tpmScheme, tpmLocation);

  if (tpmScheme[0] == "")
    tpmScheme[0] = KeyChain.getDefaultTpmScheme_();

  if (KeyChain.getTpmFactories_()[tpmScheme[0]] == undefined)
    throw new KeyChain.Error(new Error
      ("TPM scheme `" + tpmScheme[0] + "` is not supported"));
};

/**
 * @return {string}
 */
KeyChain.getDefaultPibScheme_ = function() { return PibSqlite3.getScheme(); };

/**
 * @return {string}
 */
KeyChain.getDefaultTpmScheme_ = function()
{
  // Assume we are in Node.js, so check the system.
  if (process.platform === "darwin")
    throw new KeyChain.Error(new Error
      ("TpmBackEndOsx is not implemented. You must use tpm-file."));

  return TpmBackEndFile.getScheme();
};

/**
 * Create a Pib according to the pibLocator.
 * @param {string} pibLocator The PIB locator, e.g., "pib-sqlite3:/example/dir".
 * @return {Pib} A new Pib object.
 */
KeyChain.createPib_ = function(pibLocator)
{
  var pibScheme = [null];
  var pibLocation = [null];
  KeyChain.parseAndCheckPibLocator_(pibLocator, pibScheme, pibLocation);
  var pibFactory = KeyChain.getPibFactories_()[pibScheme[0]];
  return new Pib(pibScheme[0], pibLocation[0], pibFactory(pibLocation[0]));
};

/**
 * Set up tpm according to the tpmLocator. This is called by
 * Pib.initializePromise_ after determining the correct tpmLocator.
 * @param {Tpm} tpm The Tpm to set up.
 * @param {string} tpmLocator The TPM locator, e.g., "tpm-memory:".
 * @return {Tpm} A new Tpm object.
 */
KeyChain.setUpTpm_ = function(tpm, tpmLocator)
{
  var tpmScheme = [null];
  var tpmLocation = [null];
  KeyChain.parseAndCheckTpmLocator_(tpmLocator, tpmScheme, tpmLocation);
  var tpmFactory = KeyChain.getTpmFactories_()[tpmScheme[0]];
  tpm.scheme_ = tpmScheme[0];
  tpm.location_ = tpmLocation[0];
  tpm.backEnd_ = tpmFactory(tpmLocation[0]);
};

/**
 * @param {ConfigFile} config
 * @return {string}
 */
KeyChain.getDefaultPibLocator_ = function(config)
{
  if (KeyChain.defaultPibLocator_ != null)
    return KeyChain.defaultPibLocator_;

  var clientPib = process.env.NDN_CLIENT_PIB;
  if (clientPib != undefined && clientPib != "")
    KeyChain.defaultPibLocator_ = clientPib;
  else
    KeyChain.defaultPibLocator_ = config.get
      ("pib", KeyChain.getDefaultPibScheme_() + ":");

  return KeyChain.defaultPibLocator_;
};

/**
 * @param {ConfigFile} config
 * @return {string}
 */
KeyChain.getDefaultTpmLocator_ = function(config)
{
  if (KeyChain.defaultTpmLocator_ != null)
    return KeyChain.defaultTpmLocator_;

  var clientTpm = process.env.NDN_CLIENT_TPM;
  if (clientTpm != undefined && clientTpm != "")
    KeyChain.defaultTpmLocator_ = clientTpm;
  else
    KeyChain.defaultTpmLocator_ = config.get
      ("tpm", KeyChain.getDefaultTpmScheme_() + ":");

  return KeyChain.defaultTpmLocator_;
};

/**
 * Prepare a Signature object according to signingInfo and get the signing key
 * name.
 * @param {SigningInfo} params The signing parameters.
 * @param {Array<Name>} keyName Set keyName[0] to the signing key name.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns a new Signature object
 * with the SignatureInfo, or a promise rejected with InvalidSigningInfoError
 * when the requested signing method cannot be satisfied.
 */
KeyChain.prototype.prepareSignatureInfoPromise_ = function
  (params, keyName, useSync)
{
  var identity = null;
  var key = null;
  var thisKeyChain = this;

  return SyncPromise.resolve()
  .then(function() {
    if (params.getSignerType() == SigningInfo.SignerType.NULL) {
      return thisKeyChain.pib_.getDefaultIdentityPromise(useSync)
      .then(function(localIdentity) {
        identity = localIdentity;
        return SyncPromise.resolve(null);
      }, function(err) {
        // There is no default identity, so use sha256 for signing.
        keyName[0] = SigningInfo.getDigestSha256Identity();
        return SyncPromise.resolve(new DigestSha256Signature());
      });
    }
    else if (params.getSignerType() == SigningInfo.SignerType.ID) {
      identity = params.getPibIdentity();
      if (identity == null) {
        return thisKeyChain.pib_.getIdentityPromise(params.getSignerName(), useSync)
        .then(function(localIdentity) {
          identity = localIdentity;
          return SyncPromise.resolve(null);
        }, function(err) {
          return SyncPromise.reject(new InvalidSigningInfoError(new Error
            ("Signing identity `" + params.getSignerName().toUri() +
             "` does not exist")));
        });
      }
      else
        return SyncPromise.resolve(null);
    }
    else if (params.getSignerType() == SigningInfo.SignerType.KEY) {
      key = params.getPibKey();
      if (key == null) {
        identityName = PibKey.extractIdentityFromKeyName(
          params.getSignerName());

        return thisKeyChain.pib_.getIdentityPromise(identityName, useSync)
        .then(function(localIdentity) {
          return localIdentity.getKeyPromise(params.getSignerName(), useSync)
          .then(function(localKey) {
            key = localKey;
            // We will use the PIB key instance, so reset the identity.
            identity = null;
            return SyncPromise.resolve(null);
          });
        }, function(err) {
          return SyncPromise.reject(new InvalidSigningInfoError(new Error
            ("Signing key `" + params.getSignerName().toUri() +
             "` does not exist")));
        });
      }
      else
        return SyncPromise.resolve(null);
    }
    else if (params.getSignerType() == SigningInfo.SignerType.CERT) {
      var identityName = CertificateV2.extractIdentityFromCertName
        (params.getSignerName());

      return thisKeyChain.pib_.getIdentityPromise(identityName, useSync)
      .then(function(localIdentity) {
        identity = localIdentity;
        return identity.getKeyPromise
          (CertificateV2.extractKeyNameFromCertName(params.getSignerName()), useSync)
        .then(function(localKey) {
          key = localKey;
          return SyncPromise.resolve(null);
        });
      }, function(err) {
        return SyncPromise.reject(new InvalidSigningInfoError(new Error
          ("Signing certificate `" + params.getSignerName().toUri() +
           "` does not exist")));
      });
    }
    else if (params.getSignerType() == SigningInfo.SignerType.SHA256) {
      keyName[0] = SigningInfo.getDigestSha256Identity();
      return SyncPromise.resolve(new DigestSha256Signature());
    }
    else
      // We don't expect this to happen.
      return SyncPromise.reject(new InvalidSigningInfoError(new Error
        ("Unrecognized signer type")));
  })
  .then(function(signingInfo) {
    if (signingInfo != null)
      // We already have the result (a DigestSha256Signature).
      return SyncPromise.resolve(signingInfo);
    else {
      if (identity == null && key == null)
        return SyncPromise.reject(new InvalidSigningInfoError(new Error
          ("Cannot determine signing parameters")));

      return SyncPromise.resolve()
      .then(function() {
        if (identity != null && key == null) {
          return identity.getDefaultKeyPromise(useSync)
          .then(function(localKey) {
            key = localKey;
            return SyncPromise.resolve(null);
          }, function(err) {
            return SyncPromise.reject(new InvalidSigningInfoError(new Error
              ("Signing identity `" + identity.getName().toUri() +
               "` does not have default certificate")));
          });
        }
        else
          return SyncPromise.resolve();
      })
      .then(function() {
        if (key.getKeyType() == KeyType.RSA &&
            params.getDigestAlgorithm() == DigestAlgorithm.SHA256)
          signatureInfo = new Sha256WithRsaSignature();
        else if (key.getKeyType() == KeyType.EC &&
                 params.getDigestAlgorithm() == DigestAlgorithm.SHA256)
          signatureInfo = new Sha256WithEcdsaSignature()
        else
          return SyncPromise.reject(new KeyChain.Error(new Error
            ("Unsupported key type")));

        if (params.getValidityPeriod().hasPeriod() &&
            ValidityPeriod.canGetFromSignature(signatureInfo))
          // Set the ValidityPeriod from the SigningInfo params.
          ValidityPeriod.getFromSignature(signatureInfo).setPeriod
            (params.getValidityPeriod().getNotBefore(),
             params.getValidityPeriod().getNotAfter());

        var keyLocator = KeyLocator.getFromSignature(signatureInfo);
        keyLocator.setType(KeyLocatorType.KEYNAME);
        keyLocator.setKeyName(key.getName());

        keyName[0] = key.getName();
        return SyncPromise.resolve(signatureInfo);
      });
    }
  });
};

/**
 * Sign the byte buffer using the key with name keyName.
 * @param {Buffer} buffer The input byte buffer.
 * @param {Name} keyName The name of the key.
 * @param {number} digestAlgorithm The digest algorithm as an int from the
 * DigestAlgorithm enum.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the signature Blob (or
 * an isNull Blob if the key does not exist), or a promise rejected
 * with TpmBackEnd.Error for an error in signing.
 */
KeyChain.prototype.signBufferPromise_ = function
  (buffer, keyName, digestAlgorithm, useSync)
{
  if (keyName.equals(SigningInfo.getDigestSha256Identity())) {
    var hash = Crypto.createHash('sha256');
    hash.update(buffer);
    return SyncPromise.resolve(new Blob(hash.digest(), false));
  }

  return this.tpm_.signPromise(buffer, keyName, digestAlgorithm, useSync);
};

KeyChain.defaultPibLocator_ = null // string
KeyChain.defaultTpmLocator_ = null // string
KeyChain.pibFactories_ = null // string => MakePibImpl
KeyChain.tpmFactories_ = null // string => MakeTpmBackEnd
KeyChain.defaultSigningInfo_ = new SigningInfo();
KeyChain.defaultKeyParams_ = new RsaKeyParams();

/**
 * Create an InvalidSigningInfoError which extends KeyChain.Error to indicate
 * that the supplied SigningInfo is invalid.
 * Call with: throw new InvalidSigningInfoError(new Error("message")).
 * @param {Error} error The exception created with new Error.
 * @constructor
 */
var InvalidSigningInfoError = function InvalidSigningInfoError(error)
{
  // Call the base constructor.
  KeyChain.Error.call(this, error);
}

InvalidSigningInfoError.prototype = new KeyChain.Error();
InvalidSigningInfoError.prototype.name = "InvalidSigningInfoError";

exports.InvalidSigningInfoError = InvalidSigningInfoError;

exports.InvalidSigningInfoError = InvalidSigningInfoError;

/**
 * Create a LocatorMismatchError which extends KeyChain.Error to indicate that
 * the supplied TPM locator does not match the locator stored in the PIB.
 * Call with: throw new LocatorMismatchError(new Error("message")).
 * @param {Error} error The exception created with new Error.
 * @constructor
 */
var LocatorMismatchError = function LocatorMismatchError(error)
{
  // Call the base constructor.
  KeyChain.Error.call(this, error);
}

LocatorMismatchError.prototype = new KeyChain.Error();
LocatorMismatchError.prototype.name = "LocatorMismatchError";

exports.LocatorMismatchError = LocatorMismatchError;

// Put these last to avoid a require loop.
/** @ignore */
var ConfigFile = require('../util/config-file.js').ConfigFile; /** @ignore */
var Pib = require('./pib/pib.js').Pib; /** @ignore */
var PibImpl = require('./pib/pib-impl.js').PibImpl; /** @ignore */
var PibKey = require('./pib/pib-key.js').PibKey; /** @ignore */
var PibSqlite3 = require('./pib/pib-sqlite3.js').PibSqlite3; /** @ignore */
var PibMemory = require('./pib/pib-memory.js').PibMemory;

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
var Name = require('../../name.js').Name; /** @ignore */
var WireFormat = require('../../encoding/wire-format.js').WireFormat; /** @ignore */
var X509CrlInfo = require('../certificate/x509-crl-info.js').X509CrlInfo; /** @ignore */
var LOG = require('../../log.js').Log.LOG;

/**
 * An X509CrlCache holds retrieved X509CrlInfo objects, indexed by the
 * encapsulated X.509 name of the issuer. A CRL is removed no later than
 * its nextUpdate time.
 *
 * Create an X509CrlCache.
 * @constructor
 */
var X509CrlCache = function X509CrlCache()
{
  // The key is the issuer name URI string. The value is an object with fields
  // "crlInfo" of type X509CrlInfo and "removalTime" as milliseconds since
  // Jan 1, 1970 UTC.
  // (Use a string because we can't use the Name object as the key in JavaScript.)
  this.crlsByName_ = {};
  this.nextRefreshTime_ = Number.MAX_VALUE;
};

exports.X509CrlCache = X509CrlCache;

/**
 * Insert the CRL into the cache. (This does not validate its signature.) If
 * the current time is outside of the range of the thisUpdate time and
 * nextUpdate time, then log a message and don't insert. If the thisUpdate
 * time is before the thisUpdate time of an existing CRL from the same issuer,
 * then log a message and don't insert. If a CRL exists with the same issuer
 * name, it is replaced. The inserted CRL will be removed no later than its
 * nextUpdate time.
 * @param {X509CrlInfo} crlInfo The X509CrlInfo object, which is copied.
 * @return {boolean} True for success, false if not inserted for some reason
 * such as already expired (the reason is sent to the log output).
 */
X509CrlCache.prototype.insert = function(crlInfo)
{
  var issuerNameUri = crlInfo.getIssuerName().toUri();
  var now = new Date().getTime();

  // Check if the validity period is in range.
  if (now < crlInfo.getThisUpdate()) {
    if (LOG > 2) console.log("The current time is before the CRL thisUpdate time " +
      WireFormat.toIsoString(crlInfo.getThisUpdate()) +
      ": Not adding CRL from issuer " + issuerNameUri);
    return false;
  }
  var nextUpdate = crlInfo.getNextUpdate();
  if (nextUpdate < now) {
    if (LOG > 2) console.log("The current time is already past the CRL nextUpdate time " +
      WireFormat.toIsoString(nextUpdate) + ": Not adding CRL from issuer " +
      issuerNameUri);
    return false;
  }

  // Check if a more recent CRL already exists.
  var otherCrlInfo = this.crlsByName_[issuerNameUri];
  if (otherCrlInfo && otherCrlInfo.getThisUpdate() > crlInfo.getThisUpdate()) {
    if (LOG > 2) console.log(
      "There is already a CRL from the same issuer with newer thisUpdate time: Not adding CRL with thisUpdate time " +
      WireFormat.toIsoString(crlInfo.getThisUpdate()) + " from issuer " +
      issuerNameUri);
    return false;
  }

  if (nextUpdate < this.nextRefreshTime_)
    // We need to run refresh() sooner.)
    this.nextRefreshTime_ = nextUpdate;

  var removalHours = (nextUpdate - now) / (3600 * 1000.0);
  if (LOG > 3) console.log("Adding CRL from issuer " + issuerNameUri +
    ", will remove in " + removalHours + " hours");
  // Copy the crlInfo.
  this.crlsByName_[issuerNameUri] =
    { crlInfo: new X509CrlInfo(crlInfo), removalTime: nextUpdate };

  return true;
};

/**
 * Find the certificate by the given issuer name.
 * @param {Name} issuerName The encapsulated X.509 issuer name.
 * @return {X509CrlInfo} The found X509CrlInfo, or null if not found. You must
 * not modify the returned object. If you need to modify it, then make a copy.
 */
X509CrlCache.prototype.find = function(issuerName)
{
  this.refresh_();

  var entry = this.crlsByName_[issuerName.toUri()];
  if (!entry)
    return null;
  return entry.crlInfo;
};

/**
 * Clear all CRLs from the cache.
 */
X509CrlCache.prototype.clear = function()
{
  this.crlsByName_ = {};
  this.nextRefreshTime_ = Number.MAX_VALUE;
};

/**
 * Remove all outdated CRL entries.
 */
X509CrlCache.prototype.refresh_ = function()
{
  var now = new Date().getTime();
  if (now < this.nextRefreshTime_)
    return;

  // We recompute nextRefreshTime_.
  var nextRefreshTime = Number.MAX_VALUE;
  for (var issuerNameUri in this.crlsByName_) {
    var entry = this.crlsByName_[issuerNameUri];
    if (entry.removalTime <= now) {
      if (LOG > 3) console.log("Removing cached CRL with next update " +
        WireFormat.toIsoString(entry.crlInfo.getNextUpdate()) + " from issuer " +
        issuerNameUri);
      // (In JavaScript, it is OK to delete while iterating.)
      delete this.crlsByName_[issuerNameUri];
    }
    else
      nextRefreshTime = Math.min(nextRefreshTime, entry.removalTime);
  }

  this.nextRefreshTime_ = nextRefreshTime;
};

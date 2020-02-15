'use strict'
/**
 * Models a single Permission, as part of a PermissionSet.
 * @see https://github.com/solid/web-access-control-spec for details.
 * @module permission
 */

const vocab = require('solid-namespace')
const crypto = require('crypto');
const { acl } = require('./modes')
const GroupListing = require('./group-listing')

class Agent {
  get id () {
    throw new Error('Agent.id must be implemented in subclass.')
  }

  get isSingleAgent () {
    return false
  }

  get isGroup () {
    return false
  }

  get isPublic () {
    return false
  }

  equals (other) {
    const sameClass = this.constructor.name === other.constructor.name
    const sameId = this.id === other.id
    const sameMailto = (!this.mailto && !other.mailto) ||
      (this.mailto && other.mailto &&
        this.mailto.sort().toString() === other.mailto.sort().toString())
    return sameClass && sameId && sameMailto
  }
}

class SingleAgent extends Agent {
  /**
   * @param webId {string} URL of an agent's WebID (`acl:agent`).
   *
   * @param [mailto=[]] {Array<string>} Stores the `mailto:` aliases for a given
   *   agent. Semi-unofficial functionality, used to store a user's email in the
   *   root storage .acl, to use for account recovery etc.
   */
  constructor ({ webId, mailto = [] }) {
    super()
    this.webId = webId
    this.mailto = mailto
  }

  get id () {
    return this.webId
  }

  get isSingleAgent () {
    return true
  }

  /**
   * Adds a given `mailto:` alias to this permission.
   * @param agent {String|Statement} Agent URL (or RDF `acl:agent` statement).
   */
  addMailto (agent) {
    if (typeof agent !== 'string') {
      agent = agent.object.value
    }
    if (agent.startsWith('mailto:')) {
      agent = agent.split(':')[ 1 ]
    }
    this.mailto.push(agent)
    this.mailto.sort()
  }

  rdfStatements ({ fragment, rdf }) {
    if (!this.id) {
      throw new Error('Cannot serialize - invalid Agent.')
    }
    const ns = vocab(rdf)
    const statements = [
      rdf.triple(fragment, ns.acl('agent'), rdf.namedNode(this.webId))
    ]
    for (const agentMailto of this.mailto) {
      statements.push(
        rdf.triple(fragment, ns.acl('agent'), rdf.namedNode('mailto:' + agentMailto))
      )
    }
    return statements
  }

  clone () {
    const { webId, mailto } = this
    const options = JSON.parse(JSON.stringify({ webId, mailto }))
    return new SingleAgent(options)
  }
}

class Group extends Agent {
  /**
   * @param groupUrl {string} URL of a group resource (`acl:agentGroup` or
   *   `acl:agentClass`).
   */
  constructor ({ groupUrl }) {
    super()
    this.groupUrl = groupUrl
  }

  get id () {
    return this.groupUrl
  }

  get isGroup () {
    return true
  }

  rdfStatements ({ fragment, rdf }) {
    if (!this.id) {
      throw new Error('Cannot serialize - invalid Agent.')
    }
    const ns = vocab(rdf)
    return [
      rdf.triple(fragment, ns.acl('agentGroup'), rdf.namedNode(this.groupUrl))
    ]
  }

  clone () {
    const { groupUrl } = this
    const options = JSON.parse(JSON.stringify({ groupUrl }))
    return new Group(options)
  }
}

class Everyone extends Agent {
  get id () {
    return acl.EVERYONE
  }

  get isPublic () {
    return true
  }

  clone () {
    return new Everyone()
  }

  rdfStatements ({ fragment, rdf }) {
    const ns = vocab(rdf)
    return [
      rdf.triple(fragment, ns.acl('agentClass'), ns.foaf('Agent'))
    ]
  }
}

/**
 * Models an individual permission object, for a single resource and for
 * a single webId (either agent or group). See the comments at the top
 * of the PermissionSet module for design assumptions.
 * Low-level, not really meant to be instantiated directly. Use
 * `permissionSet.addPermission()` instead.
 * @class Permission
 */
class Permission {
  /**
   * @param resourceUrl {string} URL of the resource (`acl:accessTo`) for which
   *   this permission is intended.
   *
   * @param agent {Agent}
   *
   * @param [accessModes] {Set} Set of all of the access modes (`acl:Write` etc)
   *   granted in this permission. Modified via `addMode()` and `removeMode()`.
   *
   * @param [inherit] {boolean} Does this permission apply to the contents of
   *   a container? (`acl:default`). Not used with non-container resources.
   *
   * @param [virtual=false] {boolean} Should this permission be serialized?
   *   (When writing back to an ACL resource, for example.) Used for implied
   *   (rather than explicit) permission, such as ones that are derived from
   *   `acl:Control` statements.
   */
  constructor ({ resourceUrl, agent, accessModes = new Set(), inherit = false, virtual = false } = {}) {
    this.resourceUrl = resourceUrl
    this.agent = agent
    this.accessModes = accessModes
    this.inherit = inherit
    this.virtual = virtual
  }

  get agentId () {
    return this.agent && this.agent.id
  }

  get accessType () {
    return this.inherit ? acl.DEFAULT : acl.ACCESS_TO
  }

  /**
   * Returns whether or not this permission is empty (that is, whether it has
   * any access modes like Read, Write, etc, set on it)
   * @returns {boolean}
   */
  get isEmpty () {
    return this.accessModes.size === 0
  }

  /**
   * Returns whether this permission is valid (ready to be serialized into
   * an RDF graph ACL resource). This requires all three of the following:
   *   1. Either an agent or an agentClass/group
   *   2. A resource URL (`acl:accessTo`)
   *   3. At least one access mode (read, write, etc) (returned by `isEmpty`)
   * @returns {boolean}
   */
  get isValid () {
    return !!this.agent && !!this.resourceUrl && !this.isEmpty
  }

  get isPublic () {
    return !!this.agent && this.agent.isPublic
  }

  /**
   * Compares this permission with another one.
   * Permissions are equal iff they:
   *   - Are for the same agent or group
   *   - Are intended for the same resourceUrl
   *   - Grant the same access modes
   *   - Have the same `inherit`/`acl:default` flag
   *   - Contain the same `mailto:` agent aliases.
   * @param other {Permission}
   * @returns {boolean}
   */
  equals (other) {
    const sameAgent = (!this.agent && !other.agent) ||
      (this.agent && other.agent && this.agent.equals(other.agent))
    const sameUrl = this.resourceUrl === other.resourceUrl
    const sameInherit = !!this.inherit === !!other.inherit
    const sameModes = this.allModes().sort().toString() === other.allModes().sort().toString()

    return !!sameAgent && sameUrl && sameModes && sameInherit
  }

  /**
   * Adds one or more access modes (`acl:mode` statements) to this permission.
   * @param accessMode {String|Statement|Array<String>|Array<Statement>} One or
   *   more access modes, each as either a uri, or an RDF statement.
   * @returns {Permission} Returns self, chainable.
   */
  addMode (accessMode) {
    if (Array.isArray(accessMode) || accessMode instanceof Set) {
      for (let mode of accessMode) {
        this.addModeSingle(mode)
      }
    } else {
      this.addModeSingle(accessMode)
    }
    return this
  }

  /**
   * Adds a single access mode. Internal function, used by `addMode()`.
   * @param accessMode {String|Statement} Access mode as either a uri, or an RDF
   *   statement (quad).
   * @returns {Permission} chainable
   */
  addModeSingle (accessMode) {
    if (typeof accessMode !== 'string') { // is a quad
      accessMode = accessMode.object.value
    }
    this.accessModes.add(accessMode)
    return this
  }

  /**
   * Removes one or more access modes from this permission.
   * @method removeMode
   * @param accessMode {String|Statement|Array<String>|Array<Statement>} URL
   *   representation of the access mode, or an RDF `acl:mode` triple.
   * @returns {Permission} chainable
   */
  removeMode (accessMode) {
    if (Array.isArray(accessMode)) {
      accessMode.forEach((ea) => {
        this.removeModeSingle(ea)
      })
    } else {
      this.removeModeSingle(accessMode)
    }
    return this
  }

  /**
   * Removes a single access mode from this permission. Internal use only
   * (used by `removeMode()`).
   * @method removeModeSingle
   * @private
   * @param accessMode {String|Statement} URI or RDF statement
   * @returns {Permission} chainable
   */
  removeModeSingle (accessMode) {
    if (typeof accessMode !== 'string') {
      accessMode = accessMode.object.value
    }
    this.accessModes.delete(accessMode)
    return this
  }

  /**
   * Returns a list of all access modes for this permission.
   * @method allModes
   * @return {Array<String>}
   */
  allModes () {
    return Array.from(this.accessModes)
  }

  /**
   * Tests whether this permission grant the specified access mode
   * @param accessMode {String|NamedNode} Either a named node for the access
   *   mode or a string key ('write', 'read' etc) that maps to that mode.
   * @return {Boolean}
   */
  allowsMode (accessMode) {
    // Normalize the access mode
    accessMode = acl[accessMode.toUpperCase()] || accessMode
    if (accessMode === acl.APPEND) {
      return this.allowsAppend() // Handle the Append special case
    }
    return this.accessModes.has(accessMode)
  }

  /**
   * Does this permission grant `acl:Read` access mode?
   * @method allowsRead
   * @return {Boolean}
   */
  allowsRead () {
    return this.accessModes.has(acl.READ)
  }

  /**
   * Does this permission grant `acl:Write` access mode?
   * @method allowsWrite
   * @return {Boolean}
   */
  allowsWrite () {
    return this.accessModes.has(acl.WRITE)
  }

  /**
   * Does this permission grant `acl:Append` access mode?
   * @method allowsAppend
   * @return {Boolean}
   */
  allowsAppend () {
    return this.accessModes.has(acl.APPEND) || this.accessModes.has(acl.WRITE)
  }

  /**
   * Does this permission grant `acl:Control` access mode?
   * @method allowsControl
   * @return {Boolean}
   */
  allowsControl () {
    return this.accessModes.has(acl.CONTROL)
  }

  /**
   * Merges the access modes of a given permission with the access modes of
   * this one (Set union).
   * @param other {Permission}
   * @throws {Error} Error if the other permission is for a different webId
   *   or resourceUrl (`acl:accessTo`)
   */
  mergeWith (other) {
    if (this.equals(other)) {
      return
    }
    if (this.id !== other.id) {
      throw new Error('Cannot merge permissions with different agent id or resource url (accessTo)')
    }
    for (const accessMode of other.allModes()) {
      this.addMode(accessMode)
    }
  }

  /**
   * Returns a deep copy of this permission.
   * @return {Permission}
   */
  clone () {
    const agent = this.agent ? this.agent.clone() : null
    const accessModes = new Set(this.accessModes)
    const { resourceUrl, inherit, virtual } = this
    const options = JSON.parse(JSON.stringify(
      { resourceUrl, inherit, virtual }
    ))

    return new Permission({ agent, accessModes, ...options })
  }

  /**
   * Returns an array of RDF statements representing this permission.
   * Used by `PermissionSet.serialize()`.
   * @param rdf {RDF} RDF Library
   * @return {Array<Quad>} List of RDF statements representing this Auth,
   *   or an empty array if this permission is invalid.
   */
  rdfStatements (rdf) {
    // Make sure the permission has at least one agent/group and `accessTo`
    if (!this.isValid) {
      return [] // This Permission is invalid, return empty array
    }
    // Virtual / implied permissions are not serialized
    if (this.virtual) {
      return []
    }
    const subject = rdf.namedNode(this.resourceUrl + '#' + this.hashFragment())
    const ns = vocab(rdf)

    const statements = [
      rdf.triple(subject, ns.rdf('type'), ns.acl('Authorization'))
    ].concat(
      this.agent.rdfStatements({ fragment: subject, rdf })
    )

    if (this.inherit) {
      statements.push(
        rdf.triple(subject, ns.acl('default'), rdf.namedNode(this.resourceUrl))
      )
    } else {
      statements.push(
        rdf.triple(subject, ns.acl('accessTo'), rdf.namedNode(this.resourceUrl))
      )
    }

    for (const accessMode of this.allModes()) {
      statements.push(
        rdf.triple(subject, ns.acl('mode'), rdf.namedNode(accessMode))
      )
    }

    return statements
  }

  /**
   * Returns an id based on a combination of agent/group webId and resourceUrl.
   * Used internally as a key to store this permission in a PermissionSet.
   *
   * @throws {Error} Errors if either the agent or the resourceUrl are not set.
   *
   * @return {string}
   */
  get id () {
    if (!this.agent || !this.agent.id || !this.resourceUrl) {
      throw new Error('This permission is incomplete, no id yet.')
    }

    return Permission.idFor(this.agent.id, this.resourceUrl, this.accessType)
  }

  /**
   * Returns a hashed combination of agent/group webId and resourceUrl.
   *
   * (This is not required to be crypto-secure, it's just for a convenient url
   * fragment, so using md5 is ok in this case.)
   *
   * @throws {Error} Errors if either the agent or the resourceUrl are not set.
   *
   * @return {string}
   */
  hashFragment () {
    // return this.id
    return crypto.createHash('md5').update(this.id).digest('hex')
  }

  /**
   * Utility method that creates a hash fragment key for this permission.
   * Used with graph serialization to RDF, and as a key to store permissions
   * in a PermissionSet. Exported (mainly for use in PermissionSet).
   *
   *
   *
   * @param webId {string} Agent or group web id
   * @param resourceUrl {string} Resource or container URL for this permission
   * @param [accessType='accessTo'] {string} Either 'accessTo' or 'default'
   * @returns {string}
   */
  static idFor (webId, resourceUrl, accessType = acl.ACCESS_TO) {
    return webId + '-' + resourceUrl + '-' + accessType
  }
}

class OldPermission {
  /**
   * @param resourceUrl {String} URL of the resource (`acl:accessTo`) for which
   *   this permission is intended.
   * @param [inherited=false] {Boolean} Should this permission be inherited (contain
   *   `acl:default`). Used for container ACLs.
   * @constructor
   */
  // constructor (resourceUrl, inherited = false) {
  //   /**
  //    * Hashmap of all of the access modes (`acl:Write` etc) granted to an agent
  //    * or group in this permission. Modified via `addMode()` and `removeMode()`
  //    * @property accessModes
  //    * @type {Object}
  //    */
  //   this.accessModes = new Set()
  //   /**
  //    * Type of permission, either for a specific resource ('accessTo'),
  //    * or to be inherited by all downstream resources ('default')
  //    * @property accessType
  //    * @type {String} Either 'accessTo' or 'default'
  //    */
  //   this.accessType = inherited
  //     ? acl.DEFAULT
  //     : acl.ACCESS_TO
  //   /**
  //    * URL of an agent's WebID (`acl:agent`). Inside an permission, mutually
  //    * exclusive with the `group` property. Set via `setAgent()`.
  //    * @property agent
  //    * @type {String}
  //    */
  //   this.agent = null
  //   /**
  //    * URL of a group resource (`acl:agentGroup` or `acl:agentClass`). Inside an
  //    * permission, mutually exclusive with the `agent` property.
  //    * Set via `setGroup()`.
  //    * @property group
  //    * @type {String}
  //    */
  //   this.group = null
  //   /**
  //    * Does this permission apply to the contents of a container?
  //    * (`acl:default`). Not used with non-container resources.
  //    * @property inherited
  //    * @type {Boolean}
  //    */
  //   this.inherited = inherited
  //   /**
  //    * Stores the `mailto:` aliases for a given agent. Semi-unofficial
  //    * functionality, used to store a user's email in the root storage .acl,
  //    * to use for account recovery etc.
  //    * @property mailTo
  //    * @type {Array<String>}
  //    */
  //   this.mailTo = []
  //   /**
  //    * Hashmap of which origins (http Origin: header) are allowed access to this
  //    * resource.
  //    * @property originsAllowed
  //    * @type {Object}
  //    */
  //   // this.originsAllowed = {}
  //   /**
  //    * URL of the resource for which this permission applies. (`acl:accessTo`)
  //    * @property resourceUrl
  //    * @type {String}
  //    */
  //   this.resourceUrl = resourceUrl
  //   /**
  //    * Should this permission be serialized? (When writing back to an ACL
  //    * resource, for example.) Used for implied (rather than explicit)
  //    * permission, such as ones that are derived from acl:Control statements.
  //    * @property virtual
  //    * @type {Boolean}
  //    */
  //   this.virtual = false
  // }

  /**
   * Adds one or more allowed origins (`acl:origin` statements) to this
   * permission.
   * @method addOrigin
   * @param origin {String|Statement|Array<String>|Array<Statement>} One or
   *   more origins, each as either a uri, or an RDF statement.
   * @return {Permission} Returns self, chainable.
   */
  // addOrigin (origin) {
  //   if (!origin) {
  //     return this
  //   }
  //   if (Array.isArray(origin)) {
  //     if (origin.length > 0) {
	// origin.forEach((ea) => {
  //         this.addOriginSingle(ea)
	// })
  //     }
  //   } else {
  //     this.addOriginSingle(origin)
  //   }
  //   return this
  // }

  /**
   * Adds a single allowed origin. Internal function, used by `addOrigin()`.
   * @method addOriginSingle
   * @private
   * @param origin {String|Statement} Allowed origin as either a uri, or an RDF
   *   statement.
   */
  // addOriginSingle (origin) {
  //   if (typeof origin !== 'string') {
  //     origin = origin.object.value
  //   }
  //   this.originsAllowed[ origin ] = true
  //   return this
  // }

  /**
   * Returns a list of all allowed origins for this permission.
   * @method allOrigins
   * @return {Array<String>}
   */
  // allOrigins () {
  //   return Object.keys(this.originsAllowed)
  // }

  /**
   * Does this permission grant access to requests coming from given origin?
   * @method allowsOrigin
   * @param origin {String}
   * @return {Boolean}
   */
  // allowsOrigin (origin) {
  //   return origin in this.originsAllowed
  // }

  /**
   * Returns whether or not this permission is for an agent (vs a group).
   * @method isAgent
   * @return {Boolean} Truthy value if agent is set
   */
  // isAgent () {
  //   return this.agent
  // }

  /**
   * Is this permission intended for the foaf:Agent group (that is, everyone)?
   * @method isPublic
   * @return {Boolean}
   */
  isPublic () {
    return this.group === acl.EVERYONE
  }

  /**
   * Returns whether or not this permission is for a group (vs an agent).
   * @method isGroup
   * @return {Boolean} Truthy value if group is set
   */
  isGroup () {
    return this.group
  }

  /**
   * Returns whether this permission is for a container and should be inherited
   * (that is, contain `acl:default`).
   * This is a helper function (instead of a raw attribute) to match the rest
   * of the api.
   * @method isInherited
   * @return {Boolean}
   */
  isInherited () {
    return this.inherited
  }

  /**
   * Removes one or more allowed origins from this permission.
   * @method removeOrigin
   * @param origin {String|Statement|Array<String>|Array<Statement>} URL
   *   representation of the access mode, or an RDF `acl:mode` triple.
   * @returns {removeMode}
   */
  // removeOrigin (origin) {
  //   if (Array.isArray(origin)) {
  //     origin.forEach((ea) => {
  //       this.removeOriginSingle(ea)
  //     })
  //   } else {
  //     this.removeOriginSingle(origin)
  //   }
  //   return this
  // }

  /**
   * Removes a single allowed origin from this permission. Internal use only
   * (used by `removeOrigin()`).
   * @method removeOriginSingle
   * @private
   * @param origin {String|Statement} URI or RDF statement
   */
  // removeOriginSingle (origin) {
  //   if (typeof origin !== 'string') {
  //     origin = origin.object.value
  //   }
  //   delete this.originsAllowed[ origin ]
  // }

  /**
   * Sets the agent WebID for this permission.
   * @method setAgent
   * @param agent {string|Quad|GroupListing} Agent URL (or `acl:agent` RDF triple).
   */
  setAgent (agent) {
    if (agent instanceof GroupListing) {
      return this.setGroup(agent)
    }
    if (typeof agent !== 'string') {
      // This is an RDF statement
      agent = agent.object.value
    }
    if (agent === acl.EVERYONE) {
      this.setPublic()
    } else if (this.group) {
      throw new Error('Cannot set agent, permission already has a group set')
    }
    if (agent.startsWith('mailto:')) {
      this.addMailTo(agent)
    } else {
      this.agent = agent
    }
  }

  /**
   * Sets the group WebID for this permission.
   * @method setGroup
   * @param group {string|Triple|GroupListing} Group URL (or `acl:agentClass` RDF
   *   triple).
   */
  // setGroup (group) {
  //   if (this.agent) {
  //     throw new Error('Cannot set group, permission already has an agent set')
  //   }
  //   if (group instanceof GroupListing) {
  //     group = group.listing
  //   }
  //   if (typeof group !== 'string') {
  //     // This is an RDF statement
  //     group = group.object.value
  //   }
  //   this.group = group
  // }
}

module.exports = {
  Permission,
  Agent,
  SingleAgent,
  Group,
  Everyone
}

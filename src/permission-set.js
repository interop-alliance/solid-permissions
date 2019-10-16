'use strict'
/**
 * @module permission-set
 * Models the set of Permissions in a given .acl resource.
 * @see https://github.com/solid/web-access-control-spec for details.
 * The working assumptions here are:
 *   - Model the various permissions in an ACL resource as a set of unique
 *     permissions, with one agent (or one group), and only
 *     one resource (acl:accessTo or acl:default) per permission.
 *   - If the source RDF of the ACL resource has multiple agents or multiple
 *     resources in one authorization, separate them into multiple separate
 *     Permission objects (with one agent/group and one resourceUrl each)
 *   - A single Permission object can grant access to multiple modes (read,
 *     write, control, etc)
 *   - By default, all the permissions in a container's ACL will be marked
 *     as 'to be inherited', that is will have `acl:default` set.
 */

const Permission = require('./permission')
const GroupListing = require('./group-listing')
const { acl } = require('./modes')
const vocab = require('solid-namespace')
const debug = require('debug')('solid:permissions')

const DEFAULT_ACL_SUFFIX = '.acl'
const DEFAULT_CONTENT_TYPE = 'text/turtle'
/**
 * Resource types, used by PermissionSet objects
 */
const RESOURCE = 'resource'
const CONTAINER = 'container'

/**
 * Agent type index names (used by findPermByAgent() etc)
 */
const AGENT_INDEX = 'agents'
const GROUP_INDEX = 'groups'

class PermissionSet {
  /**
   * @class PermissionSet
   * @param resourceUrl {String} URL of the resource to which this PS applies
   * @param aclUrl {String} URL of the ACL corresponding to the resource
   * @param isContainer {Boolean} Is the resource a container? (Affects usage of
   *   inherit semantics / acl:default)
   * @param [options={}] {Object} Options hashmap
   * @param [options.graph] {Graph} Parsed RDF graph of the ACL resource
   * @param [options.rdf] {RDF} RDF Library
   * @param [options.strictOrigin] {Boolean} Enforce strict origin?
   * @param [options.host] {String} Actual request uri
   * @param [options.origin] {String} Origin URI to enforce, relevant
   *   if strictOrigin is set to true
   * @param [options.webClient] {SolidWebClient} Used for save() and clear()
   * @param [options.isAcl] {Function}
   * @param [options.aclUrlFor] {Function}
   * @constructor
   */
  constructor (resourceUrl, aclUrl, isContainer, options = {}) {
    /**
     * Hashmap of all Permissions in this permission set, keyed by a hashed
     * combination of an agent's/group's webId and the resourceUrl.
     * @property permissions
     * @type {Object}
     */
    this.permissions = {}
    /**
     * The URL of the corresponding ACL resource, at which these permissions will
     * be saved.
     * @property aclUrl
     * @type {String}
     */
    this.aclUrl = aclUrl
    /**
     * Optional request host (used by checkOrigin())
     * @property host
     * @type {String}
     */
    this.host = options.host
    /**
     * Initialize the agents / groups indexes.
     * For each index type (`agents`, `groups`), permissions are indexed
     * first by `agentId`, then by access type (direct or inherited), and
     * lastly by resource. For example:
     *
     *   ```
     *   agents: {
     *     'https://alice.com/#i': {
     *       accessTo: {
     *         'https://alice.com/file1': permission1
     *       },
     *       default: {
     *         'https://alice.com/': permission2
     *       }
     *     }
     *   }
     *   ```
     * @property permsBy
     * @type {Object}
     */
    this.permsBy = {
      'agents': {}, // Perms by agent webId
      'groups': {} // Perms by group webId (also includes Public / EVERYONE)
    }
    /**
     * Cache of GroupListing objects, by group webId. Populated by `loadGroups()`.
     * @property groups
     * @type {Object}
     */
    this.groups = {}
    /**
     * RDF Library (optionally injected)
     * @property rdf
     * @type {RDF}
     */
    this.rdf = options.rdf
    /**
     * Whether this permission set is for a 'container' or a 'resource'.
     * Determines whether or not the inherit/'acl:default' attribute is set on
     * all its Permissions.
     * @property resourceType
     * @type {String}
     */
    this.resourceType = isContainer ? CONTAINER : RESOURCE
    /**
     * The URL of the resource for which these permissions apply.
     * @property resourceUrl
     * @type {String}
     */
    this.resourceUrl = resourceUrl
    /**
     * Should this permission set enforce "strict origin" policy?
     * (If true, uses `options.origin` parameter)
     * @property strictOrigin
     * @type {Boolean}
     */
    this.strictOrigin = options.strictOrigin
    /**
     * Contents of the request's `Origin:` header.
     * (used only if `strictOrigin` parameter is set to true)
     * @property origin
     * @type {String}
     */
    this.origin = options.origin
    /**
     * Solid REST client (optionally injected), used by save() and clear().
     * @type {SolidWebClient}
     */
    this.webClient = options.webClient

    // Init the functions for deriving an ACL url for a given resource
    this.aclUrlFor = options.aclUrlFor ? options.aclUrlFor : defaultAclUrlFor
    this.aclUrlFor.bind(this)
    this.isAcl = options.isAcl ? options.isAcl : defaultIsAcl
    this.isAcl.bind(this)

    // Optionally initialize from a given parsed graph
    if (options.graph) {
      this.initFromGraph(options.graph)
    }
  }

  /**
   * Adds a given Permission instance to the permission set.
   * Low-level function, clients should use `addPermission()` instead, in most
   * cases.
   * @method addSinglePermission
   * @private
   * @param perm {Permission}
   * @return {PermissionSet} Returns self (chainable)
   */
  addSinglePermission (perm) {
    var hashFragment = perm.hashFragment()
    if (hashFragment in this.permissions) {
      // An permission for this agent and resource combination already exists
      // Merge the incoming access modes with its existing ones
      this.permissions[hashFragment].mergeWith(perm)
    } else {
      this.permissions[hashFragment] = perm
    }
    if (!perm.virtual && perm.allowsControl()) {
      // If acl:Control is involved, ensure implicit rules for the .acl resource
      this.addControlPermissionsFor(perm)
    }
    // Create the appropriate indexes
    this.addToAgentIndex(perm)
    if (perm.isPublic() || perm.isGroup()) {
      this.addToGroupIndex(perm)
    }
    return this
  }

  /**
   * Creates an Permission with the given parameters, and passes it on to
   * `addPermission()` to be added to this PermissionSet.
   * Essentially a convenience factory method.
   * @method addPermissionFor
   * @private
   * @param resourceUrl {String}
   * @param inherit {Boolean}
   * @param agent {string|Quad|GroupListing} Agent URL (or `acl:agent` RDF triple).
   * @param [accessModes=[]] {string|NamedNode|Array} 'READ'/'WRITE' etc.
   * @param [origins=[]] {Array<String>} List of origins that are allowed access
   * @param [mailTos=[]] {Array<String>}
   * @return {PermissionSet} Returns self, chainable
   */
  addPermissionFor (resourceUrl, inherit, agent, accessModes = [],
    origins = [], mailTos = []) {
    let perm = new Permission(resourceUrl, inherit)
    if (agent instanceof GroupListing) {
      perm.setGroup(agent.listing)
    } else {
      perm.setAgent(agent)
    }
    perm.addMode(accessModes)
    perm.addOrigin(origins)
    mailTos.forEach(mailTo => {
      perm.addMailTo(mailTo)
    })
    this.addSinglePermission(perm)
    return this
  }

  /**
   * Adds a virtual (will not be serialized to RDF) permission giving
   * Read/Write/Control access to the corresponding ACL resource if acl:Control
   * is encountered in the actual source ACL.
   * @method addControlPermissionsFor
   * @private
   * @param perm {Permission} Permission containing an acl:Control access
   *   mode.
   */
  addControlPermissionsFor (perm) {
    let impliedPerm = perm.clone()
    impliedPerm.resourceUrl = this.aclUrlFor(perm.resourceUrl)
    impliedPerm.virtual = true
    impliedPerm.addMode(acl.ALL_MODES)
    this.addSinglePermission(impliedPerm)
  }

  /**
   * Adds a group permission for the given access mode and group web id.
   * @method addGroupPermission
   * @param webId {String}
   * @param accessMode {String|Array<String>}
   * @return {PermissionSet} Returns self (chainable)
   */
  addGroupPermission (webId, accessMode) {
    if (!this.resourceUrl) {
      throw new Error('Cannot add a permission to a PermissionSet with no resourceUrl')
    }
    var perm = new Permission(this.resourceUrl, this.isPermInherited())
    perm.setGroup(webId)
    perm.addMode(accessMode)
    this.addSinglePermission(perm)
    return this
  }

  /**
   * Adds a permission for the given access mode and agent id.
   * @method addPermission
   * @param webId {String} URL of an agent for which this permission applies
   * @param accessMode {String|Array<String>} One or more access modes
   * @param [origin] {String|Array<String>} One or more allowed origins (optional)
   * @return {PermissionSet} Returns self (chainable)
   */
  addPermission (webId, accessMode, origin) {
    if (!webId) {
      throw new Error('addPermission() requires a valid webId')
    }
    if (!accessMode) {
      throw new Error('addPermission() requires a valid accessMode')
    }
    if (!this.resourceUrl) {
      throw new Error('Cannot add a permission to a PermissionSet with no resourceUrl')
    }
    const permission = new Permission(this.resourceUrl, this.isPermInherited())
    permission.setAgent(webId)
    permission.addMode(accessMode)
    if (origin) {
      permission.addOrigin(origin)
    }
    this.addSinglePermission(permission)
    return this
  }

  /**
   * Adds a given permission to the "lookup by agent id" index.
   * Enables lookups via `findPermByAgent()`.
   * @method addToAgentIndex
   * @private
   * @param permission {Permission}
   */
  addToAgentIndex (permission) {
    let webId = permission.webId()
    let accessType = permission.accessType
    let resourceUrl = permission.resourceUrl
    let agents = this.permsBy.agents
    if (!agents[webId]) {
      agents[webId] = {}
    }
    if (!agents[webId][accessType]) {
      agents[webId][accessType] = {}
    }
    if (!agents[webId][accessType][resourceUrl]) {
      agents[webId][accessType][resourceUrl] = permission
    } else {
      agents[webId][accessType][resourceUrl].mergeWith(permission)
    }
  }

  /**
   * Adds a given permission to the "lookup by group id" index.
   * Enables lookups via `findPermByAgent()`.
   * @method addToGroupIndex
   * @private
   * @param permission {Permission}
   */
  addToGroupIndex (permission) {
    let webId = permission.webId()
    let accessType = permission.accessType
    let resourceUrl = permission.resourceUrl
    let groups = this.permsBy.groups
    if (!groups[webId]) {
      groups[webId] = {}
    }
    if (!groups[webId][accessType]) {
      groups[webId][accessType] = {}
    }
    if (!groups[webId][accessType][resourceUrl]) {
      groups[webId][accessType][resourceUrl] = permission
    } else {
      groups[webId][accessType][resourceUrl].mergeWith(permission)
    }
  }

  /**
   * Returns a list of all the Permissions that belong to this permission set.
   * Mostly for internal use.
   * @method allPermissions
   * @return {Array<Permission>}
   */
  allPermissions () {
    var permList = []
    var perm
    Object.keys(this.permissions).forEach(permKey => {
      perm = this.permissions[permKey]
      permList.push(perm)
    })
    return permList
  }

  /**
   * Tests whether this PermissionSet gives Public (acl:agentClass foaf:Agent)
   * access to a given uri.
   * @method allowsPublic
   * @param mode {String|NamedNode} Access mode (read/write/control etc)
   * @param resourceUrl {String}
   * @return {Boolean}
   */
  allowsPublic (mode, resourceUrl) {
    resourceUrl = resourceUrl || this.resourceUrl
    let publicPerm = this.findPublicPerm(resourceUrl)
    if (!publicPerm) {
      return false
    }
    return publicPerm.allowsMode(mode)
  }

  /**
   * Returns an RDF graph representation of this permission set and all its
   * Permissions. Used by `save()`.
   * @method buildGraph
   * @private
   * @param rdf {RDF} RDF Library
   * @return {Graph}
   */
  buildGraph (rdf) {
    var graph = rdf.graph()
    this.allPermissions().forEach(function (perm) {
      graph.add(perm.rdfStatements(rdf))
    })
    return graph
  }

  /**
   * Tests whether the given agent has the specified access to a resource.
   * This is one of the main use cases for this solid-permissions library.
   * Optionally performs strict origin checking (if `strictOrigin` is enabled
   * in the constructor's options).
   * @method checkAccess
   * @param resourceUrl {String}
   * @param agentId {String}
   * @param accessMode {String} Access mode (read/write/control)
   * @param [options={}] {Object} Passed through to `loadGroups()`.
   * @param [options.fetchGraph] {Function} Injected, returns a parsed graph of
   *   a remote document (group listing). Required.
   * @param [options.rdf] {RDF} RDF library
   * @throws {Error}
   * @return {Promise<Boolean>}
   */
  checkAccess (resourceUrl, agentId, accessMode, options = {}) {
    debug('Checking access for agent ' + agentId)
    // First, check to see if there is public access for this mode
    if (this.allowsPublic(accessMode, resourceUrl)) {
      debug('Public access allowed for ' + resourceUrl)
      return Promise.resolve(true)
    }
    // Next, see if there is an individual permission (for a user or a group)
    if (this.checkAccessForAgent(resourceUrl, agentId, accessMode)) {
      debug('Individual access granted for ' + resourceUrl)
      return Promise.resolve(true)
    }
    // If there are no group permissions, no need to proceed
    if (!this.hasGroups()) {
      debug('No groups permissions exist')
      return Promise.resolve(false)
    }
    // Lastly, load the remote group listings, and check for group perm
    debug('Check groups permissions')

    return this.loadGroups(options)
      .then(() => {
        return this.checkGroupAccess(resourceUrl, agentId, accessMode, options)
      })
  }

  /**
   * @param resourceUrl {String}
   * @param agentId {String}
   * @param accessMode {String} Access mode (read/write/control)
   * @throws {Error}
   * @return {Boolean}
   */
  checkAccessForAgent (resourceUrl, agentId, accessMode) {
    let perm = this.findPermByAgent(agentId, resourceUrl)
    let result = perm && this.checkOrigin(perm) && perm.allowsMode(accessMode)
    return result
  }

  /**
   * @param resourceUrl {string}
   * @param agentId {string}
   * @param accessMode {string} Access mode (read/write/control)
   * @param [options={}] {Object}
   * @param [options.fetchDocument] {Function}
   * @throws {Error}
   * @return {boolean}
   */
  checkGroupAccess (resourceUrl, agentId, accessMode, options = {}) {
    let result = false
    let membershipMatches = this.groupsForMember(agentId)
    membershipMatches.find(groupWebId => {
      debug('Looking for access rights for ' + groupWebId)
      if (this.checkAccessForAgent(resourceUrl, groupWebId, accessMode)) {
        debug('Groups access granted for ' + resourceUrl)
        result = true
      }
    })
    return result
  }

  /**
   * Tests whether a given permission allows operations from the current
   * request's `Origin` header. (The current request's origin and host are
   * passed in as options to the PermissionSet's constructor.)
   * @param permission {Permission}
   * @return {Boolean}
   */
  checkOrigin (permission) {
    if (!this.strictOrigin || // Enforcement turned off in server config
        !this.origin || // No origin - not a script, do not enforce origin
        this.origin === this.host) { // same origin is trusted
      return true
    }
    // If not same origin, check that the origin is in the explicit ACL list
    return permission.allowsOrigin(this.origin)
  }

  /**
   * Sends a delete request to a particular ACL resource. Intended to be used for
   * an existing loaded PermissionSet, but you can also specify a particular
   * URL to delete.
   * Usage:
   *
   *   ```
   *   // If you have an existing PermissionSet as a result of `getPermissions()`:
   *   solid.getPermissions('https://www.example.com/file1')
   *     .then(function (permissionSet) {
   *       // do stuff
   *       return permissionSet.clear()  // deletes that permissionSet
   *     })
   *   // Otherwise, use the helper function
   *   //   solid.clearPermissions(resourceUrl) instead
   *   solid.clearPermissions('https://www.example.com/file1')
   *     .then(function (response) {
   *       // file1.acl is now deleted
   *     })
   *   ```
   * @method clear
   * @param [webClient] {SolidWebClient}
   * @throws {Error} Rejects with an error if it doesn't know where to delete, or
   *   with any XHR errors that crop up.
   * @return {Promise<Request>}
   */
  clear (webClient) {
    webClient = webClient || this.webClient
    if (!webClient) {
      return Promise.reject(new Error('Cannot clear - no web client'))
    }
    var aclUrl = this.aclUrl
    if (!aclUrl) {
      return Promise.reject(new Error('Cannot clear - unknown target url'))
    }
    return webClient.del(aclUrl)
  }

  /**
   * Returns the number of Permissions in this permission set.
   * @method count
   * @return {Number}
   */
  get count () {
    return Object.keys(this.permissions).length
  }

  /**
   * Returns whether or not this permission set is equal to another one.
   * A PermissionSet is considered equal to another one iff:
   * - It has the same number of permissions, and each of those permissions
   *   has a corresponding one in the other set
   * - They are both intended for the same resource (have the same resourceUrl)
   * - They are both intended to be saved at the same aclUrl
   * @method equals
   * @param ps {PermissionSet} The other permission set to compare to
   * @return {Boolean}
   */
  equals (ps) {
    var sameUrl = this.resourceUrl === ps.resourceUrl
    var sameAclUrl = this.aclUrl === ps.aclUrl
    var sameResourceType = this.resourceType === ps.resourceType
    var myPermKeys = Object.keys(this.permissions)
    var otherPermKeys = Object.keys(ps.permissions)
    if (myPermKeys.length !== otherPermKeys.length) { return false }
    var samePerms = true
    var myPerm, otherPerm
    myPermKeys.forEach(permKey => {
      myPerm = this.permissions[permKey]
      otherPerm = ps.permissions[permKey]
      if (!otherPerm) {
        samePerms = false
      }
      if (!myPerm.equals(otherPerm)) {
        samePerms = false
      }
    })
    return sameUrl && sameAclUrl && sameResourceType && samePerms
  }

  /**
   * Finds and returns an permission (stored in the 'find by agent' index)
   * for a given agent (web id) and resource.
   * @method findPermByAgent
   * @private
   * @param webId {String}
   * @param resourceUrl {String}
   * @param indexType {String} Either 'default' or 'accessTo'
   * @return {Permission}
   */
  findPermByAgent (webId, resourceUrl, indexType = AGENT_INDEX) {
    let index = this.permsBy[indexType]
    if (!index[webId]) {
      // There are no permissions at all for this agent
      return false
    }
    // first check the accessTo type
    let accessToAuths = index[webId][acl.ACCESS_TO]
    let accessToMatch
    if (accessToAuths) {
      accessToMatch = accessToAuths[resourceUrl]
    }
    if (accessToMatch) {
      return accessToMatch
    }
    // then check the default/inherited type permissions
    let defaultAuths = index[webId][acl.DEFAULT]
    let defaultMatch
    if (defaultAuths) {
      // First try an exact match (resource matches the acl:default object)
      defaultMatch = defaultAuths[resourceUrl]
      if (!defaultMatch) {
        // Next check to see if resource is in any of the relevant containers
        let containers = Object.keys(defaultAuths).sort().reverse()
        // Loop through the container URLs, sorted in reverse alpha
        for (let containerUrl of containers) {
          if (resourceUrl.startsWith(containerUrl)) {
            defaultMatch = defaultAuths[containerUrl]
            break
          }
        }
      }
    }
    return defaultMatch
  }

  /**
   * Finds and returns an permission (stored in the 'find by group' index)
   * for the "Everyone" group (acl:agentClass foaf:Agent), for a given resource.
   * @method findPublicPerm
   * @private
   * @param resourceUrl {String}
   * @return {Permission}
   */
  findPublicPerm (resourceUrl) {
    return this.findPermByAgent(acl.EVERYONE, resourceUrl, GROUP_INDEX)
  }

  /**
   * Iterates over all the permissions in this permission set.
   * Convenience method.
   * Usage:
   *
   *   ```
   *   solid.getPermissions(resourceUrl)
   *     .then(function (permissionSet) {
   *       permissionSet.forEach(function (perm) {
   *         // do stuff with perm
   *       })
   *     })
   *   ```
   * @method forEach
   * @param callback {Function} Function to apply to each permission
   */
  forEach (callback) {
    this.allPermissions().forEach(perm => {
      callback.call(this, perm)
    })
  }

  /**
   * Returns a list of webIds of groups to which this agent belongs.
   * Note: Only checks loaded groups (assumes a previous `loadGroups()` call).
   * @param agentId {string}
   * @return {Array<string>}
   */
  groupsForMember (agentId) {
    let loadedGroupIds = Object.keys(this.groups)
    return loadedGroupIds
      .filter(groupWebId => {
        return this.groups[groupWebId].hasMember(agentId)
      })
  }

  /**
   * Returns a list of URIs of group permissions in this permission set
   * (those added via addGroupPermission(), etc).
   * @param [excludePublic=true] {Boolean} Should agentClass Agent be excluded?
   * @return {Array<string>}
   */
  groupUris (excludePublic = true) {
    let groupIndex = this.permsBy.groups
    let uris = Object.keys(groupIndex)
    if (excludePublic) {
      uris = uris.filter((uri) => { return uri !== acl.EVERYONE })
    }
    return uris
  }

  /**
   * Tests whether this permission set has any `acl:agentGroup` permissions
   * @return {Boolean}
   */
  hasGroups () {
    return this.groupUris().length > 0
  }

  /**
   * Creates and loads all the permissions from a given RDF graph.
   * Used by `getPermissions()` and by the constructor (optionally).
   * Usage:
   *
   *   ```
   *   var acls = new PermissionSet(resourceUri, aclUri, isContainer, {rdf: rdf})
   *   acls.initFromGraph(graph)
   *   ```
   * @method initFromGraph
   * @param graph {Dataset} RDF Graph (parsed from the source ACL)
   */
  initFromGraph (graph) {
    let ns = vocab(this.rdf)
    let authSections = graph.match(null, null, ns.acl('Authorization'))
    if (authSections.length) {
      authSections = authSections.map(match => { return match.subject })
    } else {
      // Attempt to deal with an ACL with no acl:Authorization types present.
      let subjects = {}
      authSections = graph.match(null, ns.acl('mode'))
      authSections.forEach(match => {
        subjects[match.subject.value] = match.subject
      })
      authSections = Object.keys(subjects).map(section => {
        return subjects[section]
      })
    }
    // Iterate through each grouping of authorizations in the .acl graph
    authSections.forEach(fragment => {
      // Extract the access modes
      let accessModes = graph.match(fragment, ns.acl('mode'))
      // Extract allowed origins
      let origins = graph.match(fragment, ns.acl('origin'))

      // Extract all the authorized agents
      let agentMatches = graph.match(fragment, ns.acl('agent'))
      // Mailtos only apply to agents (not groups)
      let mailTos = agentMatches.filter(isMailTo)
      // Now filter out mailtos
      agentMatches = agentMatches.filter(ea => { return !isMailTo(ea) })
      // Extract all 'Public' matches (agentClass foaf:Agent)
      let publicMatches = graph.match(fragment, ns.acl('agentClass'),
        ns.foaf('Agent'))
      // Extract all acl:agentGroup matches
      let groupMatches = graph.match(fragment, ns.acl('agentGroup'))
      groupMatches = groupMatches.map(ea => {
        return new GroupListing({ listing: ea })
      })
      // Create an Permission object for each group (accessTo and default)
      let allAgents = agentMatches
        .concat(publicMatches)
        .concat(groupMatches)
      // Create an Permission object for each agent or group
      //   (both individual (acl:accessTo) and inherited (acl:default))
      allAgents.forEach(agentMatch => {
        // Extract the acl:accessTo statements.
        let accessToMatches = graph.match(fragment, ns.acl('accessTo'))
        accessToMatches.forEach(resourceMatch => {
          let resourceUrl = resourceMatch.object.value
          this.addPermissionFor(resourceUrl, acl.NOT_INHERIT,
            agentMatch, accessModes, origins, mailTos)
        })
        // Extract inherited / acl:default statements
        let inheritedMatches = graph.match(fragment, ns.acl('default'))
          .concat(graph.match(fragment, ns.acl('defaultForNew')))
        inheritedMatches.forEach(containerMatch => {
          let containerUrl = containerMatch.object.value
          this.addPermissionFor(containerUrl, acl.INHERIT,
            agentMatch, accessModes, origins, mailTos)
        })
      })
    })
  }

  /**
   * Returns whether or not permissions added to this permission set be
   * inherited, by default? (That is, should they have acl:default set on them).
   * @method isPermInherited
   * @return {Boolean}
   */
  isPermInherited () {
    return this.resourceType === CONTAINER
  }

  /**
   * Returns whether or not this permission set has any Permissions added to it
   * @method isEmpty
   * @return {Boolean}
   */
  isEmpty () {
    return this.count === 0
  }

  /**
   * @method loadGroups
   * @param [options={}]
   * @param [options.fetchGraph] {Function} Injected, returns a parsed graph of
   *   a remote document (group listing). Required.
   * @param [options.rdf] {RDF} RDF library
   * @throws {Error}
   * @return {Promise<PermissionSet>} Resolves to self, chainable
   */
  loadGroups (options = {}) {
    let fetchGraph = options.fetchGraph
    debug('Fetching with ' + fetchGraph)
    let rdf = options.rdf || this.rdf
    if (!fetchGraph) {
      return Promise.reject(new Error('Cannot load groups, fetchGraph() not supplied'))
    }
    if (!rdf) {
      return Promise.reject(new Error('Cannot load groups, rdf library not supplied'))
    }
    let uris = this.groupUris()
    let loadActions = uris.map(uri => {
      return GroupListing.loadFrom(uri, fetchGraph, rdf, options)
    })
    return Promise.all(loadActions)
      .then(groups => {
        groups.forEach(group => {
          if (group) { this.groups[group.uri] = group }
        })
        return this
      })
  }

  /**
   * Returns the corresponding Permission for a given agent/group webId (and
   * for a given resourceUrl, although it assumes by default that it's the same
   * resourceUrl as the PermissionSet).
   * @method permissionFor
   * @param webId {String} URL of the agent or group
   * @param [resourceUrl] {String}
   * @return {Permission} Returns the corresponding Permission, or `null`
   *   if no webId is given, or if no such permission exists.
   */
  permissionFor (webId, resourceUrl) {
    if (!webId) {
      return null
    }
    resourceUrl = resourceUrl || this.resourceUrl
    var hashFragment = Permission.hashFragmentFor(webId, resourceUrl)
    return this.permissions[hashFragment]
  }

  /**
   * Deletes a given Permission instance from the permission set.
   * Low-level function, clients should use `removePermission()` instead, in most
   * cases.
   * @method removeSinglePermission
   * @param perm {Permission}
   * @return {PermissionSet} Returns self (chainable)
   */
  removeSinglePermission (perm) {
    var hashFragment = perm.hashFragment()
    delete this.permissions[hashFragment]
    return this
  }

  /**
   * Removes one or more access modes from an permission in this permission set
   * (defined by a unique combination of agent/group id (webId) and a resourceUrl).
   * If no more access modes remain for that permission, it's deleted from the
   * permission set.
   * @method removePermission
   * @param webId
   * @param accessMode {String|Array<String>}
   * @return {PermissionSet} Returns self (via a chainable function)
   */
  removePermission (webId, accessMode) {
    var perm = this.permissionFor(webId, this.resourceUrl)
    if (!perm) {
      // No permission for this webId + resourceUrl exists. Bail.
      return this
    }
    // Permission exists, remove the accessMode from it
    perm.removeMode(accessMode)
    if (perm.isEmpty()) {
      // If no more access modes remain, after removing, delete it from this
      // permission set
      this.removeSinglePermission(perm)
    }
    return this
  }

  /**
   * @method save
   * @param [options={}] {Object} Options hashmap
   * @param [options.aclUrl] {String} Optional URL to save the .ACL resource to.
   *   Defaults to its pre-set `aclUrl`, if not explicitly passed in.
   * @param [options.contentType] {string} Optional content type to serialize as
   * @throws {Error} Rejects with an error if it doesn't know where to save, or
   *   with any XHR errors that crop up.
   * @return {Promise<SolidResponse>}
   */
  save (options = {}) {
    let aclUrl = options.aclUrl || this.aclUrl
    let contentType = options.contentType || DEFAULT_CONTENT_TYPE
    if (!aclUrl) {
      return Promise.reject(new Error('Cannot save - unknown target url'))
    }
    if (!this.webClient) {
      return Promise.reject(new Error('Cannot save - no web client'))
    }
    return this.serialize({ contentType })
      .then(graph => {
        return this.webClient.put(aclUrl, graph, contentType)
      })
  }

  /**
   * Serializes this permission set (and all its Permissions) to a string RDF
   * representation (Turtle by default).
   * Note: invalid authorizations (ones that don't have at least one agent/group,
   * at least one resourceUrl and at least one access mode) do not get serialized,
   * and are instead skipped.
   * @method serialize
   * @param [options={}] {Object} Options hashmap
   * @param [options.contentType='text/turtle'] {string}
   * @param [options.rdf] {RDF} RDF Library to serialize with
   * @throws {Error} Rejects with an error if one is encountered during RDF
   *   serialization.
   * @return {Promise<String>} Graph serialized to contentType RDF syntax
   */
  serialize (options = {}) {
    let contentType = options.contentType || DEFAULT_CONTENT_TYPE
    let rdf = options.rdf || this.rdf
    if (!rdf) {
      return Promise.reject(new Error('Cannot save - no rdf library'))
    }
    let graph = this.buildGraph(rdf)
    let target = null
    let base = this.aclUrl
    return new Promise((resolve, reject) => {
      rdf.serialize(target, graph, base, contentType, (err, result) => {
        if (err) { return reject(err) }
        if (!result) {
          return reject(new Error('Error serializing the graph to ' +
            contentType))
        }
        resolve(result)
      })
    })
  }
}

/**
 * Returns the corresponding ACL uri, for a given resource.
 * This is the default template for the `aclUrlFor()` method that's used by
 * PermissionSet instances, unless it's overridden in options.
 * @param resourceUri {String}
 * @return {String} ACL uri
 */
function defaultAclUrlFor (resourceUri) {
  if (defaultIsAcl(resourceUri)) {
    return resourceUri // .acl resources are their own ACLs
  } else {
    return resourceUri + DEFAULT_ACL_SUFFIX
  }
}

/**
 * Tests whether a given uri is for an ACL resource.
 * This is the default template for the `isAcl()` method that's used by
 * PermissionSet instances, unless it's overridden in options.
 * @method defaultIsAcl
 * @param uri {String}
 * @return {Boolean}
 */
function defaultIsAcl (uri) {
  return uri.endsWith(DEFAULT_ACL_SUFFIX)
}

/**
 * Returns whether or not a given agent webId is actually a `mailto:` link.
 * Standalone helper function.
 * @param agent {String|Statement} URL string (or RDF `acl:agent` triple)
 * @return {Boolean}
 */
function isMailTo (agent) {
  if (typeof agent === 'string') {
    return agent.startsWith('mailto:')
  } else {
    return agent.object.value.startsWith('mailto:')
  }
}

PermissionSet.RESOURCE = RESOURCE
PermissionSet.CONTAINER = CONTAINER
module.exports = PermissionSet

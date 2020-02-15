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

const { Permission, SingleAgent, Group, Everyone } = require('./permission')
const GroupListing = require('./group-listing')
const { acl } = require('./modes')
const vocab = require('solid-namespace')
const { promisify } = require('util')
const rdflib = require('rdflib')

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
   * @param resourceUrl {string}
   * @param aclUrl {string}
   * @param isContainer {boolean}
   * @param rdf {RDF} rdflib library
   * @param [permissions={}] {object} Hashmap of all Permissions in this
   *   permission set, keyed by a hashed combination of an agent's/group's webId
   *   and the resourceUrl.
   */
  constructor ({ resourceUrl, aclUrl, isContainer = false, rdf = rdflib, index, permissions = {} } = {}) {
    this.resourceUrl = resourceUrl
    this.aclUrl = aclUrl || aclUrlFor(resourceUrl)
    this.isContainer = isContainer
    this.rdf = rdf
    this.permissions = permissions
    this.index = index || {
      'agents': {}, // Permissions by agent webId
      'groups': {} // Permissions by group webId (also includes Public/EVERYONE)
    }
    /**
     * Cache of GroupListing objects, by group webId. Populated by `loadGroups()`.
     */
    this.groups = {}
  }

  /**
   * Returns the number of Permissions in this permission set.
   * @returns {number}
   */
  get count () {
    return Object.keys(this.permissions).length
  }

  /**
   * Returns whether or not this permission set has any Permissions added to it
   * @returns {boolean}
   */
  get isEmpty () {
    return this.count === 0
  }

  /**
   * Tests whether this permission set has any `acl:agentGroup` permissions
   * @returns {boolean}
   */
  get hasGroups () {
    return this.groupUrls().length > 0
  }

  /**
   * Tests whether the given agent has the specified access to a resource.
   * This is one of the main use cases for this solid-permissions library.
   * Optionally performs strict origin checking (if `strictOrigin` is enabled
   * in the constructor's options).
   * @param resourceUrl {string}
   * @param agentId {string}
   * @param accessMode {string|NamedNode} Access mode (read/write/control etc)
   * @param [options={}] {object} Passed through to `loadGroups()`.
   * @param [options.fetchGraph] {Function} Injected, returns a parsed graph of
   *   a remote document (group listing). Required.
   * @param [options.rdf] {RDF} RDF library
   * @throws {Error}
   * @returns {Promise<boolean>}
   */
  async checkAccess (resourceUrl, agentId, accessMode, options = {}) {
    // First, check to see if there is public access for this mode
    if (this.allowsPublic(accessMode, resourceUrl)) {
      return true
    }
    // Next, see if there is an individual permission (for a user or a group)
    if (this.checkAccessForAgent(resourceUrl, agentId, accessMode)) {
      return true
    }
    // If there are no group permissions, no need to proceed
    if (!this.hasGroups) {
      return false
    }
    // Lastly, load the remote group listings, and check for group perm
    await this.loadGroups(options)
    return this.checkGroupAccess(resourceUrl, agentId, accessMode, options)
  }

  /**
   * Tests whether this PermissionSet gives Public (acl:agentClass foaf:Agent)
   * access to a given url.
   * @param accessMode {string|NamedNode} Access mode (read/write/control etc)
   * @param resourceUrl {string}
   * @returns {boolean}
   */
  allowsPublic (accessMode, resourceUrl) {
    resourceUrl = resourceUrl || this.resourceUrl
    const publicPermission = this.permissionByAgent(
      acl.EVERYONE, resourceUrl, GROUP_INDEX
    )
    if (!publicPermission) {
      return false
    }
    return publicPermission.allowsMode(accessMode)
  }

  /**
   * @param resourceUrl {string}
   * @param agentId {string}
   * @param accessMode {string} Access mode (read/write/control)
   *
   * @throws {Error}
   *
   * @returns {boolean}
   */
  checkAccessForAgent (resourceUrl, agentId, accessMode) {
    const permission = this.permissionByAgent(agentId, resourceUrl)
    return !!permission && permission.allowsMode(accessMode)
  }

  /**
   * @param resourceUrl {string}
   * @param agentId {string}
   * @param accessMode {string} Access mode (read/write/control)
   * @param [options={}] {Object}
   * @param [options.fetchDocument] {Function}
   * @throws {Error}
   * @returns {boolean}
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
   * Finds and returns a permission (stored in the 'find by agent' index)
   * for a given agent (web id) and resource.
   * @param agentId {string}
   * @param resourceUrl {string}
   * @param indexName {string}
   * @return {Permission}
   */
  permissionByAgent (agentId, resourceUrl, indexName = AGENT_INDEX) {
    const index = this.index[indexName]
    if (!index[agentId]) {
      // There are no permissions at all for this agent
      return false
    }
    // first check the accessTo type
    const directPermissions = index[agentId][acl.ACCESS_TO]
    let directMatch
    if (directPermissions) {
      directMatch = directPermissions[resourceUrl]
    }
    if (directMatch) {
      return directMatch
    }
    // then check the default/inherited type permissions
    const inheritedPermissions = index[agentId][acl.DEFAULT]
    let inheritedMatch
    if (inheritedPermissions) {
      // First try an exact match (resource matches the acl:default object)
      inheritedMatch = inheritedPermissions[resourceUrl]
      if (!inheritedMatch) {
        // Next check to see if resource is in any of the relevant containers
        const containers = Object.keys(inheritedPermissions).sort().reverse()
        // Loop through the container URLs, sorted in reverse alpha
        for (const containerUrl of containers) {
          if (resourceUrl.startsWith(containerUrl)) {
            inheritedMatch = inheritedPermissions[containerUrl]
            break
          }
        }
      }
    }
    return inheritedMatch
  }

  /**
   * Returns a list of all the Permissions that belong to this permission set.
   * Mostly for internal use.
   * @return {Array<Permission>}
   */
  allPermissions () {
    return Object.values(this.permissions)
  }

  /**
   * Adds an access mode to the permission for an agent id.
   * @param agentId {string} URL of an agent for which this permission applies
   * @param accessMode {string|Array<String>} One or more access modes
   * @param [inherit] {boolean} Determines access type (default/accessTo)
   *
   * @returns {PermissionSet} Returns self (chainable)
   */
  addMode ({agentId, accessMode, inherit = this.isContainer}) {
    if (!agentId) {
      throw new Error('addPermission() requires a valid webId.')
    }
    if (!accessMode) {
      throw new Error('addPermission() requires a valid accessMode.')
    }
    if (!this.resourceUrl) {
      throw new Error('Cannot add a permission to a PermissionSet with no resourceUrl.')
    }
    const permission = new Permission({
      resourceUrl: this.resourceUrl,
      inherit,
      agent: new SingleAgent({ webId: agentId })
    })
    permission.addMode(accessMode)
    return this.addPermission(permission)
  }

  /**
   * Adds a given Permission instance to the permission set.
   * @param permission {Permission}
   * @returns {PermissionSet} Returns self (chainable)
   */
  addPermission (permission) {
    const id = permission.id
    if (id in this.permissions) {
      // An permission for this agent and resource combination already exists
      // Merge the incoming access modes with its existing ones
      this.permissions[id].mergeWith(permission)
    } else {
      this.permissions[id] = permission
    }
    if (!permission.virtual && permission.allowsControl()) {
      // If acl:Control is involved, ensure implicit rules for the .acl resource
      this.addControlPermissionsFor(permission)
    }
    // Create the appropriate indexes
    this.addToIndex(AGENT_INDEX, permission)
    if (permission.isPublic || permission.isGroup) {
      this.addToIndex(GROUP_INDEX, permission)
    }
    return this
  }

  /**
   * Removes one or more access modes from an permission in this permission set
   * (defined by a unique combination of agent/group id and a resourceUrl).
   * If no more access modes remain for that permission, it's deleted from the
   * permission set.
   * @param agentId
   * @param accessMode {String|Array<String>}
   * @return {PermissionSet} Returns self (chainable function)
   */
  removeMode (agentId, accessMode) {
    const permission = this.permissionByAgent(agentId, this.resourceUrl)
    if (!permission) {
      // No permission for this agentId + resourceUrl exists. Bail.
      return this
    }
    // Permission exists, remove the accessMode from it
    permission.removeMode(accessMode)
    if (permission.isEmpty) {
      // If no more access modes remain, after removing, delete it from this
      // permission set
      this.removePermission(permission)
    }
    return this
  }

  /**
   * Deletes a given Permission instance from the permission set.
   *
   * @param permission {Permission}
   * @return {PermissionSet} Returns self (chainable)
   */
  removePermission (permission) {
    delete this.permissions[permission.id]

    this.removeFromIndex(AGENT_INDEX, permission)
    if (permission.isPublic || permission.isGroup) {
      this.removeFromIndex(GROUP_INDEX, permission)
    }
    return this
  }

  /**
   * Adds a virtual (will not be serialized to RDF) permission giving
   * Read/Write/Control access to the corresponding ACL resource if acl:Control
   * is encountered in the actual source ACL.
   * @param permission {Permission} Containing an acl:Control access mode.
   */
  addControlPermissionsFor (permission) {
    const impliedPermission = permission.clone()
    impliedPermission.resourceUrl = aclUrlFor(permission.resourceUrl)
    impliedPermission.virtual = true
    impliedPermission.addMode(acl.ALL_MODES)
    this.addPermission(impliedPermission)
  }

  /**
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
   * @param indexName {string} AGENT_INDEX or GROUP_INDEX
   * @param permission
   */
  addToIndex (indexName, permission) {
    const index = this.index[indexName]
    if (!index[permission.agentId]) {
      index[permission.agentId] = {}
    }

    if (!index[permission.agentId][permission.accessType]) {
      index[permission.agentId][permission.accessType] = {}
    }

    if (!index[permission.agentId][permission.accessType][permission.resourceUrl]) {
      index[permission.agentId][permission.accessType][permission.resourceUrl] = permission
    } else {
      index[permission.agentId][permission.accessType][permission.resourceUrl]
        .mergeWith(permission)
    }
  }

  removeFromIndex (indexName, permission) {
    const index = this.index[indexName]
    if (!index) {
      return
    }

    if (!index[permission.agentId] ||
        !index[permission.agentId][permission.accessType]) {
      return
    }

    delete index[permission.agentId][permission.accessType][permission.resourceUrl]
  }

  /**
   * Returns a list of URLs of group permissions in this permission set
   *
   * @param [excludePublic=true] {boolean} Should agentClass Agent be excluded?
   *
   * @returns {Array<string>}
   */
  groupUrls ({ excludePublic = true } = {}) {
    const urls = Object.keys(this.index.groups)
    if (excludePublic) {
      return urls.filter(url => url !== acl.EVERYONE)
    }
    return urls
  }

  /**
   * @param [options={}]
   * @param [options.fetchGraph] {Function} Injected, returns a parsed graph of
   *   a remote document (group listing). Required.
   * @param [options.rdf] {RDF} RDF library
   * @throws {Error}
   * @returns {Promise<PermissionSet>} Resolves to self, chainable
   */
  async loadGroups ({ fetchGraph, rdf = this.rdf }) {
    if (!fetchGraph) {
      throw new Error('Cannot load groups, fetchGraph() not supplied')
    }
    const urls = this.groupUrls()
    const loadActions = urls.map(url => GroupListing.loadFrom(url, fetchGraph, rdf))
    const groups = await Promise.all(loadActions)
    groups.forEach(group => {
      if (group) { this.groups[group.url] = group }
    })
    return this
  }

  /**
   * Returns a list of webIds of groups to which this agent belongs.
   * Note: Only checks loaded groups (assumes a previous `loadGroups()` call).
   * @param agentId {string}
   * @return {Array<string>}
   */
  groupsForMember (agentId) {
    const loadedGroupIds = Object.keys(this.groups)
    return loadedGroupIds
      .filter(groupId => {
        return this.groups[groupId].hasMember(agentId)
      })
  }

  /**
   * Returns an RDF graph representation of this permission set and all its
   * Permissions. Used by `save()`.
   * @param rdf {RDF} RDF Library
   * @returns {IndexedFormula} graph
   */
  buildGraph (rdf = this.rdf) {
    const graph = rdf.graph()
    for (const permission of this.allPermissions()) {
      if(!permission.virtual) {
        graph.add(permission.rdfStatements(rdf))
      }
    }
    return graph
  }

  /**
   * Serializes this permission set (and all its Permissions) to a string RDF
   * representation (Turtle by default).
   * Note: invalid authorizations (ones that don't have at least one agent/group,
   * at least one resourceUrl and at least one access mode) do not get serialized,
   * and are instead skipped.
   * @param [contentType='text/turtle'] {string}
   * @param [rdf] {RDF} RDF Library to serialize with
   *
   * @throws {Error} If one is encountered during RDF serialization.
   *
   * @return {Promise<string>} Graph serialized to contentType RDF syntax
   */
  async serialize ({ contentType = DEFAULT_CONTENT_TYPE, rdf = rdflib } = {}) {
    const graph = this.buildGraph(rdf)
    const target = null
    const base = this.aclUrl

    try {
      return promisify(rdf.serialize)(target, graph, base, contentType)
    } catch (error) {
      throw new Error(`Error serializing the graph to ${contentType}: ${error}`)
    }
  }

  /**
   * Creates and loads all the permissions from a given RDF graph.
   * Usage:
   *
   *   ```
   *   const ps = PermissionSet.fromGraph({ target, graph, rdf }
   *   // or
   *   const ps = PermissionSet.fromGraph({
   *     resourceUrl, aclUrl, isContainer, graph, rdf
   *   })
   *   ```
   *
   * Either `target` or a combination of `resourceUrl`/ `aclUrl`/`isContainer`
   *   is required.
   * @param [resourceUrl] {string}
   * @param [aclUrl] {string}
   * @param [target] {LdpTarget}
   * @param [isContainer] {boolean}
   *
   * @param graph {IndexedFormula} RDF Graph (parsed from the source ACL)
   * @param rdf {RDF} RDF library
   *
   * @returns {PermissionSet}
   */
  static fromGraph ({ resourceUrl, aclUrl, target, isContainer, graph, rdf = rdflib }) {
    const ns = vocab(rdf)

    resourceUrl = resourceUrl || (target && target.url)
    aclUrl = aclUrl || (target && target.aclUrl)
    isContainer = isContainer || !!(target && target.isContainer)

    const permissionSet = new PermissionSet({
      resourceUrl, aclUrl, isContainer, rdf
    })

    const authSections = new Set()
    for (const match of graph.match(null, ns.acl('mode'))) {
      authSections.add(match.subject.value)
    }

    // Iterate through each grouping of authorizations in the .acl graph
    for (const subject of Array.from(authSections)) {
      const fragment = graph.sym(subject)

      // Extract the access modes
      const accessModes = graph.match(fragment, ns.acl('mode'))

      const agentMatches = this.agentMatches({ fragment, graph, ns })

      // Create an Permission object for each agent or group
      //   (both individual (acl:accessTo) and inherited (acl:default))
      for (const agent of agentMatches) {
        // Extract the acl:accessTo statements.
        const resourceMatches = graph.match(fragment, ns.acl('accessTo'))
          .map(ea => ea.object.value)
        for (const resourceUrl of resourceMatches) {
          const permission = new Permission({ resourceUrl, agent, inherit: false })
          permission.addMode(accessModes)
          permissionSet.addPermission(permission)
        }

        // Extract inherited / acl:default statements
        const inheritedMatches = graph.match(fragment, ns.acl('default'))
          .concat(graph.match(fragment, ns.acl('defaultForNew')))
          .map(ea => ea.object.value)
        for (const containerUrl of inheritedMatches) {
          const permission = new Permission({
            resourceUrl: containerUrl, agent, inherit: true
          })
          permission.addMode(accessModes)
          permissionSet.addPermission(permission)
        }
      }
    }

    return permissionSet
  }

  static agentMatches ({ fragment, graph, ns }) {
    // Extract all the authorized agents (minus the mailto: terms)
    const agentMatches = graph.match(fragment, ns.acl('agent'))
      .filter(ea => !isMailTo(ea))
      .map(ea => new SingleAgent({ webId: ea.object.value }))

    // Extract all acl:agentGroup matches
    const groupMatches = graph.match(fragment, ns.acl('agentGroup'))
      .map(ea => new GroupListing({ listing: ea }))

    // See if any 'Public' matches (agentClass foaf:Agent)
    const anyPublicMatches = graph.match(fragment, ns.acl('agentClass'),
      ns.foaf('Agent')).length > 0

    const allAgents = agentMatches.concat(groupMatches)
    if (anyPublicMatches) {
      allAgents.push(new Everyone())
    }
    return allAgents
  }
}

class OldPermissionSet {
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
    this.aclUrlFor = options.aclUrlFor ? options.aclUrlFor : aclUrlFor
    this.aclUrlFor.bind(this)
    this.isAcl = options.isAcl ? options.isAcl : isAcl
    this.isAcl.bind(this)

    // Optionally initialize from a given parsed graph
    if (options.graph) {
      this.initFromGraph(options.graph)
    }
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
   * Returns whether or not permissions added to this permission set be
   * inherited, by default? (That is, should they have acl:default set on them).
   * @method isPermInherited
   * @return {Boolean}
   */
  isPermInherited () {
    return this.resourceType === CONTAINER
  }

  /**
   * Returns the corresponding Permission for a given agent/group webId (and
   * for a given resourceUrl, although it assumes by default that it's the same
   * resourceUrl as the PermissionSet).
   *
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
    const id = Permission.idFor(webId, resourceUrl)
    return this.permissions[id]
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
}

/**
 * Returns the corresponding ACL url, for a given resource.
 * This is the default template for the `aclUrlFor()` method that's used by
 * PermissionSet instances, unless it's overridden in options.
 * @param resourceUrl {string}
 * @returns {string} ACL url
 */
function aclUrlFor (resourceUrl) {
  if (!resourceUrl) {
    return undefined
  }
  if (isAcl(resourceUrl)) {
    return resourceUrl // .acl resources are their own ACLs
  } else {
    return resourceUrl + DEFAULT_ACL_SUFFIX
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
function isAcl (uri) {
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

module.exports = {
  PermissionSet,
  isAcl,
  aclUrlFor,
  isMailTo
}



const vocab = require('solid-namespace')
const debug = require('debug')('solid:permissions')

/**
 * ACL Group Listing
 * @see https://github.com/solid/web-access-control-spec#groups-of-agents
 * @class GroupListing
 */
class GroupListing {
  /**
   * @constructor
   * @param [url] {string|NamedNode} Group url as appears in ACL file
   *   (e.g. `https://example.com/groups#management`)
   * @param [listing] {string|NamedNode} Group listing document URI
   * @param [uid] {string} Value of `vcard:hasUID` object
   * @param [members={}] {Set} Set of group members, by webId
   * @param [rdf] {RDF} RDF library
   * @param [graph] {IndexedFormula} Parsed graph of the group listing document
   */
  constructor ({ url, listing, uid, members = new Set(), rdf, graph }) {
    this.url = url
    this.uid = uid
    this.members = members
    this.listing = listing
    this.rdf = rdf
    this.graph = graph
    if (this.rdf && this.graph) {
      this.initFromGraph({ url, graph: this.graph, rdf: this.rdf })
    }
  }

  /**
   * Factory function, returns a group listing, loaded and initialized
   * with the graph from its uri. Will return null if parsing fails,
   * which can be used to deny access to the resource.
   * @param url {string}
   * @param fetchGraph {Function}
   * @param rdf {RDF}
   * @param fetchOptions {Object} Options hashmap, passed through to fetchGraph()
   * @return {Promise<GroupListing|null>}
   */
  static async loadFrom (url, fetchGraph, rdf, fetchOptions = {}) {
    const group = new GroupListing({ uri: url, rdf })
    const graph = await fetchGraph(url, fetchOptions)
    return group.initFromGraph({ url, graph })
  }

  /**
   * Adds a member's web id uri to the listing
   * @param webId {string|NamedNode}
   * @return {GroupListing} Chainable
   */
  addMember (webId) {
    if (webId.value) {
      webId = webId.value
    }
    this.members.add(webId)
    return this
  }

  /**
   * Returns the number of members in this listing
   * @return {Number}
   */
  get count () {
    return this.members.size
  }

  /**
   * Tests if a webId uri is present in the members list
   * @param webId {string|NamedNode}
   * @return {Boolean}
   */
  hasMember (webId) {
    if (webId.value) {
      webId = webId.value
    }
    return this.members.has(webId)
  }

  /**
   * @param [url] {string|NamedNode} Group URI as appears in ACL file
   *   (e.g. `https://example.com/groups#management`)
   * @param [graph] {Graph} Parsed graph
   * @param [rdf] {RDF}
   * @throws {Error}
   * @returns {GroupListing} Chainable
   */
  initFromGraph ({ url = this.url, graph = this.graph, rdf = this.rdf }) {
    if (!url) {
      throw new Error('Group URI required to init from graph')
    }
    if (!graph || !rdf) {
      throw new Error('initFromGraph() - graph or rdf library missing')
    }
    const ns = vocab(rdf)
    const group = rdf.namedNode(url)
    const rdfType = graph.any(group, null, ns.vcard('Group'))
    if (!rdfType) {
      console.warn(`Possibly invalid group '${url}', missing type vcard:Group`)
    }
    this.uid = graph.anyValue(group, ns.vcard('hasUID'))
    debug('Found Group Listing with ' + group)
    graph.match(group, ns.vcard('hasMember'))
      .forEach(memberMatch => {
        this.addMember(memberMatch.object)
      })
    return this
  }
}

module.exports = GroupListing

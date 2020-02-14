'use strict'

const chai = require('chai')
chai.use(require('dirty-chai'))
const { expect } = chai
chai.should()

const sinon = require('sinon')
const rdf = require('rdflib')
const { Permission, Everyone } = require('../../src/permission')
const { acl } = require('../../src/modes')
const { PermissionSet } = require('../../src/permission-set')

const resourceUrl = 'https://alice.example.com/docs/file1'
const aclUrl = 'https://alice.example.com/docs/file1.acl'

const groupListingSource = require('../resources/group-listing-ttl')
const listingUrl = 'https://alice.example.com/work-groups'
// const groupUrl = listingUrl + '#Accounting'

const bobWebId = 'https://bob.example.com/#me'
const aliceWebId = 'https://alice.example.com/#me'

const { parseGraph } = require('./utils')

const rawAclSource = require('../resources/acl-container-ttl')
let parsedAclGraph, parsedAclGraph2, parsedGroupListing

before(async () => {
  parsedAclGraph = await parseGraph(rdf, aclUrl, rawAclSource)
  parsedGroupListing = await parseGraph(rdf, listingUrl, groupListingSource)
})

describe('PermissionSet', () => {
  describe('constructor', () => {
    it('should initialize a new set', () => {
      const ps = new PermissionSet()
      expect(ps.isContainer).to.be.false()
      expect(ps.isEmpty).to.be.true()
      expect(ps.count).to.equal(0)
      expect(ps.allPermissions()).to.eql([])
      expect(ps.hasGroups).to.be.false()
    })

    it('should init a new set for a resource', () => {
      const ps = new PermissionSet({ resourceUrl })
      expect(ps.isEmpty).to.be.true()
      expect(ps.isContainer).to.be.false()
      expect(ps.resourceUrl).to.equal(resourceUrl)
      expect(ps.aclUrl).to.equal(aclUrl, 'An acl url should be set automatically')
    })
  })

  describe('fromGraph()', () => {
    it('can create and init a PermissionSet from a graph', async () => {
      // see test/resources/acl-container-ttl.js
      const ps = PermissionSet.fromGraph({
        resourceUrl, aclUrl, isContainer: false, graph: parsedAclGraph, rdf
      })

      expect(ps.isEmpty).to.be.false()

      // Check to make sure Alice's permissions were read in correctly
      const alicePermission = ps.permissionByAgent(aliceWebId, resourceUrl)
      // 'Alice should have a permission for /docs/file1'
      expect(alicePermission).to.exist()
      expect(alicePermission.inherit).to.be.true()
      expect(alicePermission.allowsWrite() && alicePermission.allowsRead() &&
        alicePermission.allowsControl()).to.be.true()

      // Check to make sure Bob's permissions were read in correctly
      const bobPermission = ps.permissionByAgent(bobWebId, resourceUrl)
      expect(bobPermission).to.exist()
      expect(bobPermission.inherit).to.be.true()
      expect(bobPermission.allowsWrite() && bobPermission.allowsRead() &&
        bobPermission.allowsControl()).to.be.true()

      // Now check that the Public Read permission was parsed
      const publicResource = 'https://alice.example.com/profile/card'
      expect(ps.allowsPublic(acl.READ, publicResource)).to.be.true()

      const publicPermission = ps.permissionByAgent(acl.EVERYONE, publicResource)
      expect(publicPermission.isPublic).to.be.true()
      expect(publicPermission).to.exist()
      expect(publicPermission.inherit).to.be.false()
    })
  })

  describe('serialize()', () => {
    it('can serialize round trip', async () => {
      const aclUrl = 'https://localhost:8443/public/.acl'
      const resourceUrl = 'https://localhost:8443/public/'
      parsedAclGraph2 = await parseGraph(rdf, aclUrl, require('../resources/acl-container-ttl2'))
      const ps = PermissionSet.fromGraph({
        resourceUrl,
        aclUrl,
        isContainer: true,
        graph: parsedAclGraph2
      })

      const serialized = await ps.serialize()
      expect(serialized.length > 10).to.be.true()

      const newGraph = await parseGraph(rdf, aclUrl, serialized)

      const ps2 = PermissionSet.fromGraph({
        resourceUrl: 'https://localhost:8443/public/',
        aclUrl,
        isContainer: true,
        graph: newGraph
      })

      const owner = 'https://localhost:8443/web#id'
      const randomUser = 'https://someone.else.com/'
      expect(await ps2.checkAccess(resourceUrl, randomUser, acl.READ))
        .to.be.true('Should be public read')

      expect(await ps2.checkAccess(resourceUrl, owner, acl.CONTROL))
        .to.be.true('Should be owner control')
    })
  })

  describe('checkAccess()', () => {
    it('should check for Append access', async () => {
      const ps = new PermissionSet({ resourceUrl })

      ps.addPermission(aliceWebId, acl.WRITE)

      const result = await ps.checkAccess(resourceUrl, aliceWebId, acl.APPEND)
      expect(result).to.be.true('Alice should have Append access implied by Write access')
    })

    it('should check for accessTo resource', async () => {
      const containerUrl = 'https://alice.example.com/docs/'
      const ps = new PermissionSet({ resourceUrl: containerUrl })
      ps.addPermission(aliceWebId, [acl.READ, acl.WRITE])

      const result = await ps.checkAccess(containerUrl, aliceWebId, acl.WRITE)
      expect(result).to.be.true('Alice should have write access to container')

      expect(await ps.checkAccess(containerUrl, 'https://someone.else.com/', acl.WRITE))
        .to.be.false('Another user should have no write access')
    })
  })

  it('should check for inherited access', async () => {
    const containerUrl = 'https://alice.example.com/docs/'
    const ps = new PermissionSet({ resourceUrl: containerUrl, isContainer: true })

    // Now add a default / inherited permission for the container
    ps.addPermission(aliceWebId, acl.READ)

    const resourceUrl = 'https://alice.example.com/docs/file1'
    const result = await ps.checkAccess(resourceUrl, aliceWebId, acl.READ)
    expect(result).to.be.true('Alice should have inherited read access to file')

    expect(await ps.checkAccess(resourceUrl, 'https://someone.else.com/', acl.READ))
      .to.be.false('Another user should not have inherited access to file')
  })

  it('should check for public access', async () => {
    const containerUrl = 'https://alice.example.com/docs/'
    const ps = new PermissionSet({ resourceUrl: containerUrl, isContainer: true })

    // First, let's test an inherited allow public read permission
    const permission1 = new Permission({
      resourceUrl: containerUrl,
      inherit: true,
      agent: new Everyone()
    })
    permission1.addMode(acl.READ)
    ps.addSinglePermission(permission1)

    // See if this file has inherited access
    const resourceUrl = 'https://alice.example.com/docs/file1'
    const randomUser = 'https://someone.else.com/'
    expect(await ps.checkAccess(resourceUrl, randomUser, acl.READ))
      .to.be.true('Everyone should have inherited read access to file')


    // Reset the permission set, test a non-default permission
    const set2 = new PermissionSet({ resourceUrl, isContainer: false })
    const permission2 = new Permission({
      resourceUrl,
      inherit: false,
      agent: new Everyone()
    })
    permission2.addMode(acl.READ)
    set2.addSinglePermission(permission1)

    expect(await set2.checkAccess(resourceUrl, randomUser, acl.READ))
      .to.be.true('Everyone should have non-inherited read access to file')
  })

  it.skip('should check access for remote Group Listings', async () => {
    const groupAclSource = require('../resources/acl-with-group-ttl')
    const resourceUrl = 'https://alice.example.com/docs/file2.ttl'
    const aclUrl = 'https://alice.example.com/docs/file2.ttl.acl'

    const ps = PermissionSet.fromGraph({
      resourceUrl, aclUrl, isContainer: false, graph: parsedGroupListing, rdf
    })

    const fetchGraph = sinon.stub().resolves(parsedGroupListing)
    let options = { fetchGraph }

    let bob = 'https://bob.example.com/profile/card#me'
    let isContainer = false

  //   const ps = new PermissionSet(resourceUrl, aclUrl, isContainer, { rdf })
  //
  //   parseGraph(rdf, aclUrl, groupAclSource)
  //     .then(graph => {
  //       ps.initFromGraph(graph)
  //       return ps.checkAccess(resourceUrl, bob, acl.WRITE, options)
  //     })
  //     .then(hasAccess => {
  //       // External group listings have now been loaded/resolved
  //       t.ok(fetchGraph.calledWith(groupUri, options))
  //       t.ok(hasAccess, 'Bob should have access as member of group')
  })
})


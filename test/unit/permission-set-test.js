/**
 * NOTE: Test suite transitioned from Test to Mocha.
 * This is left here only for reference purposes, will be deleted soon.
 */
'use strict'

const test = require('tape')
const before = test
const sinon = require('sinon')
const rdf = require('rdflib')
const Permission = require('../../src/permission')
const { acl } = require('../../src/modes')
const PermissionSet = require('../../src/permission-set')

const resourceUrl = 'https://alice.example.com/docs/file1'
const aclUrl = 'https://alice.example.com/docs/file1.acl'
const containerUrl = 'https://alice.example.com/docs/'
const containerAclUrl = 'https://alice.example.com/docs/.acl'
const bobWebId = 'https://bob.example.com/#me'
const aliceWebId = 'https://alice.example.com/#me'
// Not really sure what group webIDs will look like, not yet implemented:
const groupWebId = 'https://devteam.example.com/something'
const { parseGraph } = require('./utils')

const rawAclSource = require('../resources/acl-container-ttl')
let parsedAclGraph

before('init graph', t => {
  return parseGraph(rdf, aclUrl, rawAclSource)
    .then(graph => {
      parsedAclGraph = graph
      t.end()
    })
    .catch(err => {
      t.fail(err)
    })
})

test('PermissionSet can add and remove agent permissions', function (t) {
  const ps = new PermissionSet(resourceUrl, aclUrl)
  t.equal(ps.aclUrl, aclUrl)
  const origin = 'https://example.com/'
  // Notice that addPermission() is chainable:
  ps
    .addMode(bobWebId, acl.READ, origin) // only allow read from origin
    .addMode(aliceWebId, [acl.READ, acl.WRITE])
  t.notOk(ps.isEmpty())
  t.equal(ps.count, 2)
  let perm = ps.permissionFor(bobWebId)
  t.equal(perm.agent, bobWebId)
  t.equal(perm.resourceUrl, resourceUrl)
  t.equal(perm.resourceType, Permission.RESOURCE)
  t.ok(perm.allowsOrigin(origin))
  t.ok(perm.allowsRead())
  t.notOk(perm.allowsWrite())
  // adding further permissions for an existing agent just merges access modes
  ps.addMode(bobWebId, acl.WRITE)
  // should still only be 2 permissions
  t.equal(ps.count, 2)
  perm = ps.permissionFor(bobWebId)
  t.ok(perm.allowsWrite())

  // Now remove the added permission
  ps.removeMode(bobWebId, acl.READ)
  // Still 2 permissions, agent1 has a WRITE permission remaining
  t.equal(ps.count, 2)
  perm = ps.permissionFor(bobWebId)
  t.notOk(perm.allowsRead())
  t.ok(perm.allowsWrite())

  // Now, if you remove the remaining WRITE permission from agent1, that whole
  // permission is removed
  ps.removeMode(bobWebId, acl.WRITE)
  t.equal(ps.count, 1, 'Only one permission should remain')
  t.notOk(ps.permissionFor(bobWebId),
    'No permission for agent1 should be found')
  t.end()
})

test('PermissionSet no duplicate permissions test', function (t) {
  const ps = new PermissionSet(resourceUrl, aclUrl)
  // Now add two identical permissions
  ps.addMode(aliceWebId, [acl.READ, acl.WRITE])
  ps.addMode(aliceWebId, [acl.READ, acl.WRITE])
  t.equal(ps.count, 1, 'Duplicate permissions should be eliminated')
  t.end()
})

test('PermissionSet can add and remove group permissions', function (t) {
  const ps = new PermissionSet(resourceUrl)
  // Let's add an agentGroup permission
  ps.addGroupPermission(groupWebId, [acl.READ, acl.WRITE])
  t.equal(ps.count, 1)
  const perm = ps.permissionFor(groupWebId)
  t.equal(perm.group, groupWebId)
  ps.removeMode(groupWebId, [acl.READ, acl.WRITE])
  t.ok(ps.isEmpty())
  t.end()
})

test('iterating over a PermissionSet', function (t) {
  const ps = new PermissionSet(resourceUrl, aclUrl)
  ps
    .addMode(bobWebId, acl.READ)
    .addMode(aliceWebId, [acl.READ, acl.WRITE])
  ps.forEach(function (perm) {
    t.ok(perm.hashFragment() in ps.permissions)
  })
  t.end()
})

test.skip('a PermissionSet() for a container', function (t) {
  const isContainer = true
  const ps = new PermissionSet(containerUrl, aclUrl, isContainer)
  t.ok(ps.isPermInherited(),
    'A PermissionSet for a container should be inherited by default')
  ps.addMode(bobWebId, acl.READ)
  const perm = ps.permissionFor(bobWebId)
  t.ok(perm.isInherited(),
    'An permission intended for a container should be inherited by default')
  t.end()
})

test('a PermissionSet() for a resource (not container)', function (t) {
  const ps = new PermissionSet(containerUrl)
  t.notOk(ps.isPermInherited())
  ps.addMode(bobWebId, acl.READ)
  const perm = ps.permissionFor(bobWebId)
  t.notOk(perm.isInherited(),
    'An permission intended for a resource should not be inherited by default')
  t.end()
})

test('a PermissionSet can be initialized from an .acl graph', function (t) {

})

test('PermissionSet equals test 1', function (t) {
  const ps1 = new PermissionSet()
  const ps2 = new PermissionSet()
  t.ok(ps1.equals(ps2))
  t.end()
})

test('PermissionSet equals test 2', function (t) {
  const ps1 = new PermissionSet(resourceUrl)
  const ps2 = new PermissionSet()
  t.notOk(ps1.equals(ps2))
  ps2.resourceUrl = resourceUrl
  t.ok(ps1.equals(ps2))

  ps1.aclUrl = aclUrl
  t.notOk(ps1.equals(ps2))
  ps2.aclUrl = aclUrl
  t.ok(ps1.equals(ps2))
  t.end()
})

test('PermissionSet equals test 3', function (t) {
  const ps1 = new PermissionSet(containerUrl, containerAclUrl,
    PermissionSet.CONTAINER)
  const ps2 = new PermissionSet(containerUrl, containerAclUrl)
  t.notOk(ps1.equals(ps2))
  ps2.resourceType = PermissionSet.CONTAINER
  t.ok(ps1.equals(ps2))
  t.end()
})

test('PermissionSet equals test 4', function (t) {
  const ps1 = new PermissionSet(resourceUrl)
  ps1.addMode(aliceWebId, acl.READ)
  const ps2 = new PermissionSet(resourceUrl)
  t.notOk(ps1.equals(ps2))
  ps2.addMode(aliceWebId, acl.READ)
  t.ok(ps1.equals(ps2))
  t.end()
})

test('PermissionSet serialized & deserialized round trip test', function (t) {
  const ps = new PermissionSet(containerUrl, containerAclUrl,
    PermissionSet.CONTAINER, { graph: parsedAclGraph, rdf })
  // console.log(ps.serialize())
  t.ok(ps.equals(ps), 'A PermissionSet should equal itself')
  // Now check to make sure serialize() & reparse results in the same set
  return ps.serialize()
    .then((serializedTurtle) => {
      // Now that the PermissionSet is serialized to a Turtle string,
      // let's re-parse that string into a new graph
      return parseGraph(rdf, containerAclUrl, serializedTurtle)
    })
    .then(parsedGraph => {
      const ps2 = new PermissionSet(containerUrl, containerAclUrl,
        PermissionSet.CONTAINER, { graph: parsedGraph, rdf })
      // console.log(ps2.serialize())
      t.ok(ps.equals(ps2),
        'A PermissionSet serialized and re-parsed should equal the original one')
      t.end()
    })
    .catch(err => {
      console.log(err)
      t.fail(err)
    })
})

test('PermissionSet allowsPublic() test', function (t) {
  const ps = new PermissionSet(containerUrl, containerAclUrl,
    PermissionSet.CONTAINER, { graph: parsedAclGraph, rdf })
  const otherUrl = 'https://alice.example.com/profile/card'
  t.ok(ps.allowsPublic(acl.READ, otherUrl),
    'Alice\'s profile should be public-readable')
  t.notOk(ps.allowsPublic(acl.WRITE, otherUrl),
    'Alice\'s profile should not be public-writable')
  t.end()
})

test('PermissionSet serialize() no rdf test', t => {
  const ps = new PermissionSet()
  ps.serialize()
    .then(() => {
      t.fail('Serialize should not succeed with no rdf lib')
    })
    .catch(err => {
      t.equal(err.message, 'Cannot save - no rdf library')
      t.end()
    })
})

test('PermissionSet serialize() rdflib errors test', t => {
  const ps = new PermissionSet(resourceUrl, aclUrl, false,
    { rdf, graph: parsedAclGraph })
  ps.serialize({ contentType: 'invalid' })
    .then(() => {
      t.fail('Serialize should not succeed with an rdflib error')
    })
    .catch(err => {
      t.ok(err.message.startsWith('Serialize: Content-type invalid'))
      t.end()
    })
})

test('PermissionSet save() test', t => {
  const resourceUrl = 'https://alice.example.com/docs/file1'
  const aclUrl = 'https://alice.example.com/docs/file1.acl'
  const isContainer = false
  const putStub = sinon.stub().returns(Promise.resolve())
  const mockWebClient = {
    put: putStub
  }
  const ps = new PermissionSet(resourceUrl, aclUrl, isContainer,
    { rdf, graph: parsedAclGraph, webClient: mockWebClient })
  let serializedGraph
  ps.serialize()
    .then(ttl => {
      serializedGraph = ttl
      return ps.save()
    })
    .then(() => {
      t.ok(putStub.calledWith(aclUrl, serializedGraph, 'text/turtle'),
        'ps.save() should result to a PUT to .acl url')
      t.end()
    })
    .catch(err => {
      console.log(err)
      t.fail()
    })
})

test('PermissionSet save() no aclUrl test', t => {
  let nullAclUrl
  const ps = new PermissionSet(resourceUrl, nullAclUrl, false,
    { rdf, graph: parsedAclGraph })
  ps.save()
    .then(() => {
      t.fail('ps.save() should not succeed with no acl url set')
    })
    .catch(err => {
      t.equal(err.message, 'Cannot save - unknown target url')
      t.end()
    })
})

test('PermissionSet save() no web client test', t => {
  const ps = new PermissionSet(resourceUrl, aclUrl, false,
    { rdf, graph: parsedAclGraph })
  ps.save()
    .then(() => {
      t.fail('ps.save() should not succeed with no web client set')
    })
    .catch(err => {
      t.equal(err.message, 'Cannot save - no web client')
      t.end()
    })
})

test('PermissionSet parsing acl with agentGroup', t => {
  const groupAclSource = require('../resources/acl-with-group-ttl')
  const resourceUrl = 'https://alice.example.com/docs/file2.ttl'
  const aclUrl = 'https://alice.example.com/docs/file2.ttl.acl'
  const groupUrl = 'https://alice.example.com/work-groups#Accounting'

  const isContainer = false
  const ps = new PermissionSet(resourceUrl, aclUrl, isContainer, { rdf })
  parseGraph(rdf, aclUrl, groupAclSource)
    .then(graph => {
      ps.initFromGraph(graph)
      // Check to make sure
      const perm = ps.findPermByAgent(groupUrl, resourceUrl)
      t.ok(perm, 'Should have parsed the aclGroup permission')
      t.equals(perm.group, groupUrl, 'Permission should have .group set')
      t.ok(perm.isGroup())
      t.end()
    })
    .catch(err => {
      console.log(err)
      t.fail(err)
    })
})

test('PermissionSet groupUris() test', t => {
  const resourceUrl = 'https://alice.example.com/docs/file2.ttl'
  const ps = new PermissionSet(resourceUrl)
  ps.addGroupPermission(acl.EVERYONE, acl.READ)
  // By default, groupUris() excludes the Public agentClass
  t.deepEquals(ps.groupUrls(), [])
  t.notOk(ps.hasGroups())
  const groupUrl = 'https://alice.example.com/work-groups#Accounting'
  ps.addGroupPermission(groupUrl, acl.WRITE)
  t.equals(ps.groupUrls().length, 1)
  t.ok(ps.hasGroups())
  const excludePublic = false
  t.equals(ps.groupUrls(excludePublic).length, 2)
  t.end()
})

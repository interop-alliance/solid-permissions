'use strict'

const test = require('tape')
const rdf = require('rdflib')
const ns = require('solid-namespace')(rdf)
const Permission = require('../../src/permission')
const { acl } = require('../../src/modes')

const resourceUrl = 'https://bob.example.com/docs/file1'
const agentWebId = 'https://bob.example.com/profile/card#me'
// Not really sure what group webIDs will look like, not yet implemented:
const groupWebId = 'https://devteam.example.com/something'

test('a new Permission()', t => {
  let auth = new Permission()
  t.notOk(auth.isAgent())
  t.notOk(auth.isGroup())
  t.notOk(auth.isPublic())
  t.notOk(auth.webId())
  t.notOk(auth.resourceUrl)
  t.equal(auth.accessType, acl.ACCESS_TO)
  t.deepEqual(auth.mailTo, [])
  t.deepEqual(auth.allOrigins(), [])
  t.deepEqual(auth.allModes(), [])
  t.notOk(auth.isInherited(),
    'An Permission should not be inherited (acl:default) by default')
  t.ok(auth.isEmpty(), 'a new Permission should be empty')
  t.end()
})

test('a new Permission for a container', t => {
  let auth = new Permission(resourceUrl, acl.INHERIT)
  t.equal(auth.resourceUrl, resourceUrl)
  t.notOk(auth.webId())
  t.notOk(auth.allowsRead())
  t.notOk(auth.allowsWrite())
  t.notOk(auth.allowsAppend())
  t.notOk(auth.allowsControl())
  t.ok(auth.isInherited(),
    'Permissions for containers should be inherited by default')
  t.equal(auth.accessType, acl.DEFAULT)
  t.end()
})

test('Permission allowsMode() test', t => {
  let auth = new Permission()
  auth.addMode(acl.WRITE)
  t.ok(auth.allowsMode(acl.WRITE), 'auth.allowsMode() should work')
  t.end()
})

test('an Permission allows editing permission modes', t => {
  let auth = new Permission()
  auth.addMode(acl.CONTROL)
  t.notOk(auth.isEmpty(), 'Adding an access mode means no longer empty')
  t.ok(auth.allowsControl(), 'Adding Control mode failed')
  t.notOk(auth.allowsRead(), 'Control mode should not imply Read')
  t.notOk(auth.allowsWrite(), 'Control mode should not imply Write')
  t.notOk(auth.allowsAppend(), 'Control mode should not imply Append')
  // Notice addMode() is chainable:
  auth
    .addMode(acl.READ)
    .addMode(acl.WRITE)
  t.ok(auth.allowsRead(), 'Adding Read mode failed')
  t.ok(auth.allowsWrite(), 'Adding Write mode failed')
  t.equals(auth.allModes().length, 3)
  auth.removeMode(acl.READ)
  t.notOk(auth.allowsRead(), 'Removing Read mode failed')
  auth.removeMode(acl.CONTROL)
  t.notOk(auth.allowsControl(), 'Removing Control mode failed')

  // Note that removing Append mode while retaining Write mode has no effect
  auth.removeMode(acl.APPEND)
  t.ok(auth.allowsWrite(), 'Removing Append should not remove Write mode')
  t.ok(auth.allowsAppend(),
    'Removing Append while retaining Write mode should have no effect')

  auth.removeMode(acl.WRITE)
  t.notOk(auth.allowsWrite(), 'Removing Write mode failed')
  t.end()
})

test('an Permission can add or remove multiple modes', t => {
  let auth = new Permission()
  auth.addMode([acl.READ, acl.WRITE, acl.CONTROL])
  t.ok(auth.allowsRead() && auth.allowsWrite() && auth.allowsControl())
  auth.removeMode([acl.WRITE, acl.READ])
  t.notOk(auth.allowsRead() && auth.allowsWrite())
  t.ok(auth.allowsControl())
  t.end()
})

test('an Permission can only have either an agent or a group', t => {
  let auth1 = new Permission()
  auth1.setAgent(agentWebId)
  t.equal(auth1.agent, agentWebId)
  // Try to set a group while an agent already set
  t.throws(function () {
    auth1.setGroup(groupWebId)
  }, 'Trying to set a group for an auth with an agent should throw an error')
  // Now try the other way -- setting an agent while a group is set
  let auth2 = new Permission()
  auth2.setGroup(groupWebId)
  t.equal(auth2.group, groupWebId)
  t.throws(function () {
    auth2.setAgent(agentWebId)
  }, 'Trying to set an agent for an auth with a group should throw an error')
  t.end()
})

test('acl.WRITE implies acl.APPEND', t => {
  let auth = new Permission()
  auth.addMode(acl.WRITE)
  t.ok(auth.allowsWrite())
  t.ok(auth.allowsAppend(), 'Adding Write mode implies granting Append mode')
  // But not the other way around
  auth = new Permission()
  auth.addMode(acl.APPEND)
  t.ok(auth.allowsAppend(), 'Adding Append mode failed')
  t.notOk(auth.allowsWrite(), 'Adding Append mode should not grant Write mode')

  auth.removeMode(acl.WRITE)
  t.ok(auth.allowsAppend(),
    'Removing Write mode when the auth only had Append mode should do nothing')

  auth.removeMode(acl.APPEND)
  t.notOk(auth.allowsAppend(), 'Removing Append mode failed')
  t.end()
})

test('an Permission can grant Public access', t => {
  let auth = new Permission()
  t.notOk(auth.isPublic(), 'An permission is not public access by default')

  auth.setPublic()
  t.ok(auth.isPublic(), 'setPublic() results in public access')
  t.equal(auth.group, acl.EVERYONE)
  t.notOk(auth.agent)

  auth = new Permission()
  auth.setGroup(acl.EVERYONE)
  t.ok(auth.isPublic(),
    'Adding group access to everyone should result in public access')
  t.ok(auth.group, 'Public access permission is a group permission')
  t.notOk(auth.agent, 'A public access auth should have a null agent')

  auth = new Permission()
  auth.setAgent(acl.EVERYONE)
  t.ok(auth.isPublic(),
    'Setting the agent to everyone should be the same as setPublic()')
  t.end()
})

test('an webId is either the agent or the group id', t => {
  let auth = new Permission()
  auth.setAgent(agentWebId)
  t.equal(auth.webId(), auth.agent)
  auth = new Permission()
  auth.setGroup(groupWebId)
  t.equal(auth.webId(), auth.group)
  t.end()
})

test('hashFragment() on an incomplete permission should fail', t => {
  let auth = new Permission()
  t.throws(function () {
    auth.hashFragment()
  }, 'hashFragment() should fail if both webId AND resourceUrl are missing')
  auth.setAgent(agentWebId)
  t.throws(function () {
    auth.hashFragment()
  }, 'hashFragment() should fail if either webId OR resourceUrl are missing')
  t.end()
})

test('Permission.isValid() test', t => {
  let auth = new Permission()
  t.notOk(auth.isValid(), 'An empty permission should not be valid')
  auth.resourceUrl = resourceUrl
  t.notOk(auth.isValid())
  auth.setAgent(agentWebId)
  t.notOk(auth.isValid())
  auth.addMode(acl.READ)
  t.ok(auth.isValid())
  auth.agent = null
  auth.setGroup(groupWebId)
  t.ok(auth.isValid())
  t.end()
})

test('Permission origins test', t => {
  let auth = new Permission()
  let origin = 'https://example.com/'
  auth.addOrigin(origin)
  t.deepEqual(auth.allOrigins(), [origin])
  t.ok(auth.allowsOrigin(origin))
  auth.removeOrigin(origin)
  t.deepEqual(auth.allOrigins(), [])
  t.notOk(auth.allowsOrigin(origin))
  t.end()
})

test('Comparing newly constructed Permissions', t => {
  let auth1 = new Permission()
  let auth2 = new Permission()
  t.ok(auth1.equals(auth2))
  t.end()
})

test('Comparing Permissions, for a resource', t => {
  let auth1 = new Permission(resourceUrl)
  let auth2 = new Permission()
  t.notOk(auth1.equals(auth2))
  auth2.resourceUrl = resourceUrl
  t.ok(auth1.equals(auth2))
  t.end()
})

test('Comparing Permissions setting Agent', t => {
  let auth1 = new Permission()
  auth1.setAgent(agentWebId)
  let auth2 = new Permission()
  t.notOk(auth1.equals(auth2))
  auth2.setAgent(agentWebId)
  t.ok(auth1.equals(auth2))
  t.end()
})

test('Comparing Permissions with same permissions', t => {
  let auth1 = new Permission()
  auth1.addMode([acl.READ, acl.WRITE])
  let auth2 = new Permission()
  t.notOk(auth1.equals(auth2))
  auth2.addMode([acl.READ, acl.WRITE])
  t.ok(auth1.equals(auth2))
  t.end()
})

test('Comparing Permissions with resource, also permission', t => {
  let auth1 = new Permission(resourceUrl, acl.INHERIT)
  let auth2 = new Permission(resourceUrl)
  t.notOk(auth1.equals(auth2))
  auth2.inherited = acl.INHERIT
  t.ok(auth1.equals(auth2))
  t.end()
})

test('Comparing Permissions with email', t => {
  let auth1 = new Permission()
  auth1.addMailTo('alice@example.com')
  let auth2 = new Permission()
  t.notOk(auth1.equals(auth2))
  auth2.addMailTo('alice@example.com')
  t.ok(auth1.equals(auth2))
  t.end()
})

test('Comparing Permissions with origin', t => {
  let origin = 'https://example.com/'
  let auth1 = new Permission()
  auth1.addOrigin(origin)
  let auth2 = new Permission()
  t.notOk(auth1.equals(auth2))
  auth2.addOrigin(origin)
  t.ok(auth1.equals(auth2))
  t.end()
})

test('Permission.clone() test', t => {
  let auth1 = new Permission(resourceUrl, acl.INHERIT)
  auth1.addMode([acl.READ, acl.WRITE])
  let auth2 = auth1.clone()
  t.ok(auth1.equals(auth2))
  t.end()
})

test('Permission serialize group test', t => {
  let auth = new Permission(resourceUrl)
  auth.addMode(acl.READ)
  let groupUrl = 'https://example.com/work-group'
  auth.setGroup(groupUrl)
  // Serialize the permission
  let triples = auth.rdfStatements(rdf)
  let groupTriple = triples.find((triple) => {
    return triple.predicate.equals(ns.acl('agentGroup'))
  })
  t.ok(groupTriple, 'Serialized auth should have an agentGroup triple')
  t.equals(groupTriple.object.value, groupUrl)
  t.end()
})

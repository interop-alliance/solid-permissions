'use strict'

const chai = require('chai')
chai.use(require('dirty-chai'))
const { expect } = chai
chai.should()

const rdf = require('rdflib')
const ns = require('solid-namespace')(rdf)
const acl = require('../../src/')
const { Permission, SingleAgent, Group, Everyone } = require('../../src/permission')

const resourceUrl = 'https://bob.example.com/docs/file1'
const aliceWebId = 'https://alice.example.com#me'

describe('Permission', () => {
  describe('a new Permission', () => {
    it('a new non-inherited permission', () => {
      const p = new Permission()
      expect(p.inherit).to.be.false()
      expect(p.accessType).to.eql(acl.ACCESS_TO)
      expect(p.virtual).to.be.false()
      expect(p.isValid).to.be.false()
      expect(p.allModes()).to.eql([])
      expect(p.isPublic).to.be.false()
      expect(p.isEmpty).to.be.true()
    })

    it('a new inherited permission', () => {
      const p = new Permission({ inherit: true })
      expect(p.inherit).to.be.true()
      expect(p.accessType).to.eql(acl.DEFAULT)
      expect(p.virtual).to.be.false()
      expect(p.isValid).to.be.false()
      expect(p.allModes()).to.eql([])
      expect(p.isPublic).to.be.false()
      expect(p.isEmpty).to.be.true()
    })
  })

  describe('addMode()', () => {
    it('can add multiple modes', () => {
      const p = new Permission()
      p.addMode([acl.READ, acl.WRITE, acl.CONTROL])
      expect(p.allowsRead() && p.allowsAppend() && p.allowsWrite() &&
        p.allowsControl()).to.be.true()
    })
  })

  describe('allModes()', () => {
    it('can return a list of all modes for this permission', () => {
      const p = new Permission()
      p.addModeSingle(acl.READ)
      p.addMode([acl.READ, acl.WRITE, acl.CONTROL])

      expect(p.allModes()).to.eql([
        'http://www.w3.org/ns/auth/acl#Read',
        'http://www.w3.org/ns/auth/acl#Write',
        'http://www.w3.org/ns/auth/acl#Control'
      ])
    })
  })

  describe('isPublic', () => {
    it('new empty permission should not be public', () => {
      const p = new Permission()
      expect(p.isPublic).to.be.false()
    })

    it('a permission with an agent or group should not be public', () => {
      const p1 = new Permission({ agent: new SingleAgent({ webId: aliceWebId }) })
      expect(p1.isPublic).to.be.false()
      const p2 = new Permission({ agent: new Group({ groupUrl: 'https://example.com/group' }) })
      expect(p2.isPublic).to.be.false()
    })

    it('a permission with Everyone should be public', () => {
      const p1 = new Permission({ agent: new Everyone() })
      expect(p1.isPublic).to.be.true()
    })
  })

  describe('isValid', () => {
    it('should be true for resource + agent + mode', () => {
      const p = new Permission()
      expect(p.isValid).to.be.false()

      p.addMode(acl.READ)
      expect(p.isValid).to.be.false()

      p.agent = new SingleAgent({ webId: aliceWebId })
      expect(p.isValid).to.be.false()

      p.resourceUrl = resourceUrl
      expect(p.isValid).to.be.true()
    })
  })

  describe('equals()', () => {
    it('should compare two newly created permissions', () => {
      const p1 = new Permission()
      const p2 = new Permission()
      expect(p1.equals(p2))
    })

    it('should compare on agent', () => {
      const perm1 = new Permission({ agent: new SingleAgent({ webId: aliceWebId }) })
      const perm2 = new Permission()
      expect(perm1.equals(perm2)).to.be.false()
      perm2.agent = new SingleAgent({ webId: aliceWebId })
      expect(perm1.equals(perm2)).to.be.true()
    })

    it('should compare based on agent mailto', () => {
      const perm1 = new Permission({ agent: new SingleAgent({ webId: aliceWebId }) })
      perm1.agent.addMailto('alice@example.com')
      const perm2 = new Permission({ agent: new SingleAgent({ webId: aliceWebId }) })

      expect(perm1.equals(perm2)).to.be.false()

      perm2.agent.addMailto('alice@example.com')
      expect(perm1.equals(perm2)).to.be.true()
    })

    it('should compare on resource', () => {
      const perm1 = new Permission({ resourceUrl })
      const perm2 = new Permission()
      expect(perm1.equals(perm2)).to.be.false()

      perm2.resourceUrl = resourceUrl
      expect(perm1.equals(perm2)).to.be.true()
    })

    it('should compare on modes', () => {
      const perm1 = new Permission()
      perm1.addMode([acl.READ, acl.WRITE])
      const perm2 = new Permission()
      expect(perm1.equals(perm2)).to.be.false()
      perm2.addMode([acl.READ, acl.WRITE])
      expect(perm1.equals(perm2)).to.be.true()
    })

    it('should compare on inherit', () => {
      const perm1 = new Permission({ resourceUrl, inherit: true })
      const perm2 = new Permission({ resourceUrl })
      expect(perm1.equals(perm2)).to.be.false()
      perm2.inherit = true
      expect(perm1.equals(perm2)).to.be.true()
    })

    describe('clone()', () => {
      it('should compare two cloned permissions', () => {
        const perm1 = new Permission({ resourceUrl, inherited: true })
        perm1.addMode([acl.READ, acl.WRITE])
        const perm2 = perm1.clone()
        expect(perm1.equals(perm2)).to.be.true()
      })
    })
  })

  describe('removeMode()', () => {
    it('can remove added modes', () => {
      const p = new Permission()
      p.addMode([acl.READ, acl.WRITE, acl.CONTROL])
      p.removeMode([acl.WRITE, acl.READ])

      expect(p.allowsRead() && p.allowsWrite()).to.be.false()
      expect(p.allowsControl()).to.be.true()
    })

    it('understands Write and Append', () => {
      const p = new Permission()
      p.addMode(acl.WRITE)

      p.removeMode(acl.APPEND)
      expect(p.allowsWrite()).to.be.true('Removing Append should not remove Write mode')
      expect(p.allowsAppend()).to.be.true('Removing Append while retaining Write mode should have no effect')
    })
  })

  describe('allowsMode()', () => {
    it('round trip addMode/allowsMode', () => {
      const p = new Permission()
      p.addMode(acl.WRITE)
      expect(p.allowsMode(acl.WRITE)).to.be.true()
    })

    it('acl.WRITE implies acl.APPEND', () => {
      let p = new Permission()
      // Adding Write mode implies granting Append mode
      p.addMode(acl.WRITE)
      expect(p.allowsWrite()).to.be.true()
      expect(p.allowsAppend()).to.be.true()
      expect(p.allowsMode(acl.APPEND)).to.be.true()

      // But not the other way around
      p = new Permission()
      p.addMode(acl.APPEND)
      expect(p.allowsAppend()).to.be.true()
      // Adding Append mode should not grant Write mode
      expect(p.allowsWrite()).to.be.false()

      // Removing Write mode when the perm only had Append mode should do nothing
      p.removeMode(acl.WRITE)
      expect(p.allowsAppend()).to.be.true()

      p.removeMode(acl.APPEND)
      expect(p.allowsAppend()).to.be.false()
    })
  })

  describe('rdfStatements', () => {
    it('should serialize agent groups', () => {
      const perm = new Permission({
        resourceUrl,
        agent: new Group({ groupUrl: 'https://example.com/work-group' })
      })
      perm.addMode(acl.READ)

      // Serialize the permission
      const triples = perm.rdfStatements(rdf)

      const groupTriple = triples.find((triple) => {
        return triple.predicate.equals(ns.acl('agentGroup'))
      })
      expect(groupTriple).to.exist('Serialized permission should have an agentGroup triple')
      expect(groupTriple.object.value).to.equal('https://example.com/work-group')
    })
  })
})

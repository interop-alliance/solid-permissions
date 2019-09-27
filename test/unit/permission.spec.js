'use strict'

const chai = require('chai')
const { expect } = chai
chai.should()

const acl = require('../../src/')
const { Permission } = acl

describe('Permission', () => {
  describe('addMode()', () => {
    it('can add multiple modes', () => {
      const p = new Permission()
      p.addMode([acl.READ, acl.WRITE, acl.CONTROL])
      expect(p.allowsRead() && p.allowsWrite() && p.allowsControl())
        .to.be.true
    })
  })

  describe('removeMode()', () => {
    it('can remove added modes', () => {
      const p = new Permission()
      p.addMode([acl.READ, acl.WRITE, acl.CONTROL])
      p.removeMode([acl.WRITE, acl.READ])

      expect(p.allowsRead() && p.allowsWrite()).to.be.false
      expect(p.allowsControl()).to.be.true
    })
  })

  describe('allowsMode()', () => {
    it('round trip addMode/allowsMode', () => {
      const p = new Permission()
      p.addMode(acl.WRITE)
      p.allowsMode(acl.WRITE).should.be.true
    })

    it('acl.WRITE implies acl.APPEND', () => {
      let p = new Permission()
      // Adding Write mode implies granting Append mode
      p.addMode(acl.WRITE)
      expect(p.allowsWrite()).to.be.true
      expect(p.allowsAppend()).to.be.true

      // But not the other way around
      p = new Permission()
      p.addMode(acl.APPEND)
      expect(p.allowsAppend()).to.be.true
      // Adding Append mode should not grant Write mode
      expect(p.allowsWrite()).to.be.false

      // Removing Write mode when the perm only had Append mode should do nothing
      p.removeMode(acl.WRITE)
      expect(p.allowsAppend()).to.be.true

      p.removeMode(acl.APPEND)
      expect(p.allowsAppend()).to.be.false
    })
  })
})


'use strict'
/**
 * @module permissions
 */

const { PermissionSet } = require('./permission-set')
const { Permission, Agent, SingleAgent, Group, Everyone } = require('./permission')
const aclModes = require('./modes')

module.exports = {
  PermissionSet,
  Permission,
  Agent,
  SingleAgent,
  Group,
  Everyone,
  ...aclModes.acl
}

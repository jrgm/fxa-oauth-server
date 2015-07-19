/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const Joi = require('joi');
const hex = require('buf').to.hex;

const auth = require('../../auth');
const db = require('../../db');
const validators = require('../../validators');

function serialize(client) {
  return {
    id: hex(client.id),
    name: client.name,
    image_uri: client.imageUri,
    redirect_uri: client.redirectUri,
    terms_uri: client.termsUri,
    privacy_uri: client.privacyUri,
    can_grant: client.canGrant,
    // XXX TODO: a future PR will remove legacy "whitelisted" attr
    whitelisted: client.trusted,
    trusted: client.trusted
  };
}

module.exports = {
  auth: {
    strategy: auth.AUTH_STRATEGY,
    scope: [auth.SCOPE_CLIENT_MANAGEMENT]
  },
  response: {
    schema: {
      clients: Joi.array().includes(
        Joi.object().keys({
          id: validators.clientId,
          name: Joi.string().required(),
          image_uri: Joi.string().allow(''),
          redirect_uri: Joi.string().allow('').required(),
          terms_uri: Joi.string().allow('').required(),
          privacy_uri: Joi.string().allow('').required(),
          can_grant: Joi.boolean().required(),
          // XXX TODO: a future PR will remove legacy "whitelisted" attr
          whitelisted: Joi.boolean().required(),
          trusted: Joi.boolean().required()
        })
      )
    }
  },
  handler: function listEndpoint(req, reply) {
    var developerEmail = req.auth.credentials.email;

    db.getClients(developerEmail).done(function(clients) {
      reply({
        clients: clients.map(serialize)
      });
    }, reply);
  }
};

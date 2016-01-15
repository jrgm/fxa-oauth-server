#!/usr/bin/env node
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const unbuf = require('buf').unbuf.hex;

const P = require('../lib/promise');

process.env.NODE_ENV = 'dev'
process.env.DB = 'mysql'

const config = require('../lib/config');
const encrypt = require('../lib/encrypt');
const logger = require('../lib/logging')('db');
const db = require('../lib/db/mysql');
const unique = require('../lib/unique');

var fs = require('fs');
const yaml = require('js-yaml');

function clientEquals(configClient, dbClient) {
  var props = Object.keys(configClient);

  for (var i = 0; i < props.length; i++) {
    var prop = props[i];
    var configProp = unbuf(configClient[prop]);
    var dbProp = unbuf(dbClient[prop]);
    if (configProp !== dbProp) {
      logger.debug('clients.differ', {
        prop: prop,
        configProp: configProp,
        dbProp: dbProp
      });
      return false;
    }
  }
  return true;
}

function convertClientToConfigFormat(client) {
  var out = {};
  for (var key in client) {
    if (key === 'createdAt') {
      continue;
    } else if (key === 'hashedSecret') {
      out.hashedSecret = unbuf(client.hashedSecret);
    } else if (key === 'trusted' || key === 'canGrant') {
      out[key] = !!client[key]; // db stores booleans as 0 or 1.
    } else if (key === 'termsUri' || key === 'privacyUri') {
      // these are optional in the config
      if (client[key]) { out[key] = client[key]; }
    } else if (typeof client[key] !== 'function') {
      out[key] = unbuf(client[key]);
    }
  }
  return out;
}

function preClients(clients, conn) {
  if (!clients || !clients.length) {
    return;
  }

  logger.debug('predefined.loading', { clients: clients });
  return P.all(clients.map(function(c) {
    if (c.secret) {
      console.error('Do not keep client secrets in the config file.'
                    + ' Use the `hashedSecret` field instead.\n\n'
                    + '\tclient=%s has `secret` field\n'
                    + '\tuse hashedSecret="%s" instead',
                    c.id,
                    unbuf(encrypt.hash(c.secret)));
      process.exit(1);
    }

    // ensure the required keys are present.
    var REQUIRED_CLIENTS_KEYS = [ 'id', 'hashedSecret', 'name', 'imageUri',
                                  'redirectUri', 'trusted', 'canGrant' ];
    REQUIRED_CLIENTS_KEYS.forEach(function(key) {
      if (!(key in c)) {
        var data = { key: key, name: c.name || 'unknown' };
        logger.error('client.missing.keys', data);
        process.exit(1);
      }
    });

    // ensure booleans are boolean and not undefined
    c.trusted = !!c.trusted;
    c.canGrant = !!c.canGrant;

    return conn.getClient(c.id).then(function(client) {
      if (client) {
        client = convertClientToConfigFormat(client);
        logger.info('client.compare', { id: c.id });
        if (clientEquals(client, c)) {
          logger.info('client.compare.equal', { id: c.id });
        } else {
          logger.warn('client.compare.differs', {
            id: c.id,
            before: client,
            after: c
          });
        }
      } else {
        logger.info('client.compare.missing', { id: c.id });
      }
    });
  }));
}

function main() {
  var file = process.argv[2]
  if (!file) {
    console.log('Usage:', process.argv[1], '/path/to/yaml/file')
    process.exit(1)
  }

  var clients;
  if (file.match(/\.json$/)) {
    clients = require(file)['clients']
  } else if (file.match(/\.yaml$/)) {
    clients = yaml.safeLoad(fs.readFileSync(file, 'utf8'))['fxa_oauth::clients']
  }

  //console.log(JSON.stringify(clients))
  if (!clients) { 
    return
  }
  

  db.connect(config.get('mysql'))
    .then(function(conn) {
      return preClients(clients, conn)
    })
    .then(function() {
      process.exit(0)
    })
}

main()

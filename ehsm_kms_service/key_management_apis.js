const { _result } = require('./function')
const logger = require('./logger')

const cmkFileds = [
  '_id',
  '_rev',
  'keyid',
  'keyBlob',
  'creator',
  'creationDate',
  'expireTime',
  'alias',
  'keyspec',
  'origin',
  'keyState',
]

const listKey = async (appid, res, DB) => {
  const query = {
    selector: {
      creator: appid,
    },
    fields: [
      'keyid',
      'creationDate',
      'expireTime',
      'alias',
      'keyspec',
      'keyState',
    ],
    limit: 10000,
  }
  DB.partitionedFind('cmk', query)
    .then((cmk_res) => {
      res.send(_result(200, 'successful', { list: cmk_res.docs }))
    })
    .catch((err) => {
      res.send(_result(400, 'listKey failed', { err }))
    })
}

const deleteALLKey = async (appid, res, DB) => {
  const query = {
    selector: {
      creator: appid,
    },
    fields: ['_id', '_rev'],
    limit: 10000,
  }
  DB.partitionedFind('cmk', query)
    .then((cmks_res) => {
      if (cmks_res.docs.length > 0) {
        for (const cmk_item of cmks_res.docs) {
          cmk_item._deleted = true
        }
        DB.bulk({ docs: cmks_res.docs })
          .then(() => {
            res.send(_result(200, 'successful'))
          }) // delete all cmks
          .catch((err) => {
            res.send(_result(400, 'deleteALLKey failed', { err }))
          })
      } else {
        res.send(_result(200, 'successful'))
      }
    })
    .catch((err) => {
      res.send(_result(400, 'deleteALLKey failed', { err }))
    })
}

const deleteKey = (appid, payload, res, DB) => {
  const query = {
    selector: {
      creator: appid,
      _id: `cmk:${payload.keyid}`,
    },
    fields: ['_id', '_rev'],
    limit: 1,
  }
  DB.partitionedFind('cmk', query)
    .then((cmks_res) => {
      if (cmks_res.docs.length > 0) {
        const { _id, _rev } = cmks_res.docs[0]
        DB.destroy(_id, _rev)
          .then(() => {
            res.send(_result(200, 'successful'))
          }) // delete one cmk
          .catch((err) => {
            res.send(_result(400, 'deleteKey failed', { err }))
          })
      } else {
        res.send(_result(200, 'successful'))
      }
    })
    .catch((err) => {
      res.send(_result(400, 'deleteKey failed', { err }))
    })
}

const enableKey = (appid, payload, res, DB) => {
  const query = {
    selector: {
      _id: `cmk:${payload.keyid}`,
      creator: appid,
    },
    fields: cmkFileds,
    limit: 1,
  }
  DB.partitionedFind('cmk', query)
    .then((cmks_res) => {
      if (cmks_res.docs.length > 0) {
        cmks_res.docs[0].keyState = 1
        DB.insert(cmks_res.docs[0])
          .then(() => {
            res.send(_result(200, 'successful'))
          })
          .catch((err) => {
            res.send(_result(400, 'enableKey failed', { err }))
          })
      } else {
        res.send(_result(400, 'not find this keyid'))
      }
    })
    .catch((err) => {
      res.send(_result(400, 'enableKey failed', { err }))
    })
}

const disableKey = (appid, payload, res, DB) => {
  const query = {
    selector: {
      _id: `cmk:${payload.keyid}`,
      creator: appid,
    },
    fields: cmkFileds,
    limit: 1,
  }
  DB.partitionedFind('cmk', query)
    .then((cmks_res) => {
      if (cmks_res.docs.length > 0) {
        cmks_res.docs[0].keyState = 0
        DB.insert(cmks_res.docs[0])
          .then(() => {
            res.send(_result(200, 'successful'))
          })
          .catch((err) => {
            try {
              res.send(_result(400, 'disableKey failed', { err }))
            } catch (error) {
              logger.error(error)
            }
          })
      } else {
        res.send(_result(400, 'not find this keyid'))
      }
    })
    .catch((err) => {
      res.send(_result(400, 'disableKey failed', { err }))
    })
}
/**
 *
 */
module.exports = {
  listKey,
  deleteKey,
  deleteALLKey,
  enableKey,
  disableKey,
}

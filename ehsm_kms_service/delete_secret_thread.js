const { base64_decode } = require('./function')

const logger = require('./logger')

// Set a queue to record the waiting time
var delete_task_queue = {}

/**
 * remove a timer from exist timer by key
 * @param {Object} DB : database control
 * @param {Object} key : key form exist timer
 * @returns
 */
const remove_delete_task = (secretName, appid) => {
    try {
        //Delete thread when thread exists
        if (delete_task_queue[secretName + '_' + appid] != undefined) {
            clearTimeout(delete_task_queue[secretName + '_' + appid].timer)
        }
        delete delete_task_queue[secretName + '_' + appid];
    } catch (error) {
        logger.error(error)
    }
}

/**
 * public interface, add a new delete task into the delete queue with the secret name.
 * @param {String} appid : appid of user
 * @param {Object} DB : database control
 * @param {Object} secretName : The name of the secret. eg. 'secretName01'
 * @param {Object} plannedDeleteTime : planned delete time for secret eg. '1659931644416'
 * @returns
 */
const add_delete_task = (DB, appid, secretName, plannedDeleteTime) => {
    try {
        let delayMillisecond = plannedDeleteTime - new Date().getTime()
        let needAdd = true
        let key = secretName + '_' + appid
        // process exist timer, 
        // If the new time is within plus or minus 10 seconds of the original time, keep the original plan unchanged; otherwise, clear the original plan and add again
        if (delete_task_queue.hasOwnProperty(key)) {
            if (delete_task_queue[key].plannedDeleteTime + 10000 > plannedDeleteTime && delete_task_queue[key].plannedDeleteTime - 10000 < plannedDeleteTime) {
                needAdd = false
            } else {
                clearTimeout(delete_task_queue[key].timer)
            }
        }
        //If the planned delete time exceeds 12 hours, the thread will not be started
        if (delayMillisecond > 12 * 1000 * 60 * 60) {
            needAdd = false
        }
        if (needAdd) {
            //Force delete according to planned deletion time
            let timer = setTimeout(async () => {
                try {
                    const forceDeleteData = require('./secret_manager_apis').forceDeleteData
                    if (await forceDeleteData(DB, appid, secretName)) {
                        logger.info(`delete secret thread :: The ${base64_decode(secretName)} delete success`)
                    } else {
                        logger.error(`delete secret thread :: The ${base64_decode(secretName)} delete failed`)
                    }
                } catch (error) {
                    logger.error(error)
                }
                // remove exist timer
                remove_delete_task(secretName, appid, DB)
            }, delayMillisecond, DB, appid, secretName)
            //add delete task in queue
            delete_task_queue[key] = {
                timer,
                plannedDeleteTime
            }
        }
    } catch (error) {
        logger.error(error)
    }
}

/**
 * Initialize the delete thread and call it when the server starts
 * @param {Object} DB : database control
 * @returns
 */
const _secret_delete_timer = (DB) => {
    //Execute timer every six hours
    const timer = setInterval(async () => {
        try {
            //Find secretName and appid in secret_metadata through planeddeletetime
            const query_plannedDeleteTime = {
                selector: {
                    deleteTime: { "$ne": null }
                },
                fields: ['appid', 'secretName', 'plannedDeleteTime']
            }
            let plannedDeleteTime_res = await DB.partitionedFind('secret_metadata', query_plannedDeleteTime)
            if (plannedDeleteTime_res.docs.length > 0) {
                for (var i = 0; i < plannedDeleteTime_res.docs.length; i++) {
                    //add deleted tasks by planning deletetime
                    add_delete_task(DB, plannedDeleteTime_res.docs[i]['appid'],
                        plannedDeleteTime_res.docs[i]['secretName'],
                        plannedDeleteTime_res.docs[i]['plannedDeleteTime'])
                }
            } else {
                return
            }
        } catch (error) {
            logger.error(error)
        }
    }, 6 * 1000 * 60 * 60, DB)
    return { timer }
}

module.exports = {
    _secret_delete_timer,
    add_delete_task,
    remove_delete_task
}

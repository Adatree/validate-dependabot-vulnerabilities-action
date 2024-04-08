require('./sourcemap-register.cjs');/******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ 857:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __nccwpck_require__) => {

"use strict";
__nccwpck_require__.r(__webpack_exports__);
const {Octokit} = require('octokit')

const errorMessage = 'Build contains vulnerabilities that violate Adatree\'s infosec policy. Please check dependabot alerts.'
const millisecondsInOneDay = 24 * 60 * 60 * 1000

const validateDependencies = async () => {
    const auth = process.env.GH_TOKEN
    const owner = 'Adatree'
    const openState = 'open'
    const octokit = new Octokit({auth})
    const repo = process.env.GITHUB_REPOSITORY.split('/')[1]
    console.log(`Retrieving dependabot alerts for repository ${repo}`)
    const response = await octokit.request('GET /repos/{owner}/{repo}/dependabot/alerts{?state,severity,ecosystem,package,manifest,scope,sort,direction,page,per_page,before,after,first,last}', {
        owner,
        repo
    })
    const relevantAlerts = response.data.filter(alert => alert.state === openState)
    if (relevantAlerts.length === 0) {
        console.log('Build is safe and respects the Adatree infosec policy')
    } else {
        console.log(relevantAlerts)
        const alertsGroupedBySeverity = relevantAlerts.reduce((acc, alert) => {
            const {severity} = alert.security_vulnerability
            acc[severity] = acc[severity] || []
            acc[severity].push(alert)
            return acc
        }, {})
        const {critical, high, medium} = alertsGroupedBySeverity
        validateCriticalAlerts(critical)
        validateHighAlerts(high)
        validateMediumAlerts(medium)
        console.log('Dependabot alerts identified but none violates Adatree\'s infosec policy.')
    }
}

// 48 hours
const validateCriticalAlerts = alerts => validateAlert(alerts, new Date().getTime() - millisecondsInOneDay * 2)

// 2 weeks
const validateHighAlerts = alerts => validateAlert(alerts, new Date().getTime() - millisecondsInOneDay * 14)

// 1 month
const validateMediumAlerts = alerts => validateAlert(alerts, new Date().getTime() - millisecondsInOneDay * 30)

const validateAlert = (alerts = [], timestamp) => {
    alerts.forEach(alert => {
        const publishedAt = Date.parse(alert.security_advisory.published_at)
        if (publishedAt < timestamp && alert.security_vulnerability.first_patched_version) {
            console.log(`patch is available and a fix is due - ${JSON.stringify(alert, null, 2)}`)
            throw new Error(errorMessage)
        }
    })
}

module.exports = {validateDependencies, millisecondsInOneDay}


/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __nccwpck_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		var threw = true;
/******/ 		try {
/******/ 			__webpack_modules__[moduleId](module, module.exports, __nccwpck_require__);
/******/ 			threw = false;
/******/ 		} finally {
/******/ 			if(threw) delete __webpack_module_cache__[moduleId];
/******/ 		}
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/make namespace object */
/******/ 	(() => {
/******/ 		// define __esModule on exports
/******/ 		__nccwpck_require__.r = (exports) => {
/******/ 			if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 				Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
/******/ 			}
/******/ 			Object.defineProperty(exports, '__esModule', { value: true });
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/compat */
/******/ 	
/******/ 	if (typeof __nccwpck_require__ !== 'undefined') __nccwpck_require__.ab = __dirname + "/";
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry need to be wrapped in an IIFE because it need to be isolated against other modules in the chunk.
(() => {
const {validateDependencies} = __nccwpck_require__(857)

async function run() {
  await validateDependencies()
}

run();

})();

module.exports = __webpack_exports__;
/******/ })()
;
//# sourceMappingURL=index.cjs.js.map
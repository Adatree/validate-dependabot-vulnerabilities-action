const {Octokit} = require('octokit')

const validateDependencies = async () => {
    const auth = process.env.GITHUB_PAT
    const owner = 'Adatree'
    const openState = 'open'
    const octokit = new Octokit({auth})
    const repo = 'test'
    const response = await octokit.request('GET /repos/{owner}/{repo}/dependabot/alerts{?state,severity,ecosystem,package,manifest,scope,sort,direction,page,per_page,before,after,first,last}', {
        owner,
        repo})
    const relevantAlerts = response.filter(alert => alert.state === openState)
    if (relevantAlerts.length === 0) {
        console.log('Build is safe and respects the Adatree infosec policy')
    } else {
        const alertsGroupedBySeverity = relevantAlerts.reduce((acc, alert) => {
            const {severity} = alert.vulnerabilities
            acc[severity] = acc[severity] ?? []
            acc[severity].push(alert)
            return acc
        }, {})
        const {critical, high, medium} = alertsGroupedBySeverity
        validateCriticalAlerts(critical)
        validateHighAlerts(high)
        validateMediumAlerts(medium)
    }
}

// 48 hours
const validateCriticalAlerts = alerts => {

}

// 2 weeks
const validateHighAlerts = alerts => {

}

// 1 month
const validateMediumAlerts = alerts => {

}

module.exports = validateDependencies

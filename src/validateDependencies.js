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
        console.log(alert.security_advisory.published_at)
        const publishedAt = Date.parse(alert.security_advisory.published_at)
        console.log(publishedAt)
        console.log(timestamp)
        if (publishedAt < timestamp) {
            throw new Error(errorMessage)
        }
    })
}

module.exports = {validateDependencies, millisecondsInOneDay}

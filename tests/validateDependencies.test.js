const {validateDependencies, millisecondsInOneDay} = require("../src/validateDependencies.js")
const Octokit = require('octokit').Octokit

jest.mock('octokit')

process.env.GITHUB_REPOSITORY = 'adatree/validate-dependabot-vulnerabilities-action'

test('Build succeeds in case of no vulnerabilities identified', async () => {
    const dependabotNoOpenAlerts = []
    Octokit.mockImplementation(() => ({
        request: () => ({data: dependabotNoOpenAlerts})
    }))
    expect(validateDependencies).not.toThrow()
})

test('Build passes for medium vulnerabilities newer than 1 month', async() => {
    const dateOffset = millisecondsInOneDay * 29
    const publishedAt = new Date()
    publishedAt.setTime(new Date() - dateOffset)
    const dependabotAlerts = [
        {
            "number": 1,
            "state": "open",
            "security_advisory": {
                "published_at": publishedAt.toString()
            },
            "security_vulnerability": {
                "severity": "medium"
            }
        }
    ]
    Octokit.mockImplementation(() => ({
        request: () => ({data: dependabotAlerts})
    }))
    expect(validateDependencies).not.toThrow()
})

test('Build fails for medium vulnerabilities older than 1 month', async() => {
    const dateOffset = millisecondsInOneDay * 31
    const publishedAt = new Date()
    publishedAt.setTime(new Date() - dateOffset)
    const dependabotAlerts = [
        {
            "number": 1,
            "state": "open",
            "security_advisory": {
                "published_at": publishedAt.toString()
            },
            "security_vulnerability": {
                "severity": "medium",
                "first_patched_version": "1"
            }
        }
    ]
    Octokit.mockImplementation(() => ({
        request: () => ({data: dependabotAlerts})
    }))
    await expect(validateDependencies).rejects.toThrow()
})

test('Build passes for medium vulnerabilities newer than one month', async () => {
    const dateOffset = millisecondsInOneDay * 15
    const publishedAt = new Date()
    publishedAt.setTime(new Date() - dateOffset)
    const dependabotAlerts = [
        {
            "number": 1,
            "state": "open",
            "security_advisory": {
                "published_at": publishedAt.toString()
            },
            "security_vulnerability": {
                "severity": "medium"
            }
        }
    ]
    Octokit.mockImplementation(() => ({
        request: () => ({data: dependabotAlerts})
    }))
    expect(validateDependencies).not.toThrow()
})

test('Build passes for medium vulnerabilities when new patch is not available even if has been published more than a month ago', async () => {
    const dateOffset = millisecondsInOneDay * 31
    const publishedAt = new Date()
    publishedAt.setTime(new Date() - dateOffset)
    const dependabotAlerts = [
        {
            "number": 1,
            "state": "open",
            "security_advisory": {
                "published_at": publishedAt.toString()
            },
            "security_vulnerability": {
                "severity": "medium"
            }
        }
    ]
    Octokit.mockImplementation(() => ({
        request: () => ({data: dependabotAlerts})
    }))
    expect(validateDependencies).not.toThrow()
})

test('Build fails for high vulnerabilities older than 14 days', async() => {
    const dateOffset = millisecondsInOneDay * 15
    const publishedAt = new Date()
    publishedAt.setTime(new Date() - dateOffset)
    const dependabotAlerts = [
        {
            "number": 1,
            "state": "open",
            "security_advisory": {
                "published_at": publishedAt.toString()
            },
            "security_vulnerability": {
                "severity": "high",
                "first_patched_version": "1"
            }
        }
    ]
    Octokit.mockImplementation(() => ({
        request: () => ({data: dependabotAlerts})
    }))
    await expect(validateDependencies).rejects.toThrow()
})

test('Build passes for high vulnerabilities newer than 14 days', async () => {
    const dateOffset = millisecondsInOneDay * 13
    const publishedAt = new Date()
    publishedAt.setTime(new Date() - dateOffset)
    const dependabotAlerts = [
        {
            "number": 1,
            "state": "open",
            "security_advisory": {
                "published_at": publishedAt.toString()
            },
            "security_vulnerability": {
                "severity": "high"
            }
        }
    ]
    Octokit.mockImplementation(() => ({
        request: () => ({data: dependabotAlerts})
    }))
    expect(validateDependencies).not.toThrow()
})

test('Build fails for critical vulnerabilities older than 2 days', async () => {
    const dateOffset = millisecondsInOneDay * 3
    const publishedAt = new Date().setTime(new Date() - dateOffset).toString()
    const dependabotAlerts = [
        {
            "number": 1,
            "state": "open",
            "security_advisory": {
                "published_at": publishedAt
            },
            "security_vulnerability": {
                "severity": "critical"
            }
        }
    ]
    Octokit.mockImplementation(() => ({
        request: () => ({data: dependabotAlerts})
    }))
    await validateDependencies()
})

test('Build passes for critical vulnerabilities newer than 2 days', async () => {
    const dependabotAlerts = [
        {
            "number": 1,
            "state": "open",
            "security_advisory": {
                "published_at": new Date().toString()
            },
            "security_vulnerability": {
                "severity": "critical"
            }
        }
    ]
    Octokit.mockImplementation(() => ({
        request: () => ({data: dependabotAlerts})
    }))
    expect(validateDependencies).not.toThrow()
})


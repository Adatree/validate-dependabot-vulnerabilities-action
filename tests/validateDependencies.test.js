const {validateDependencies, millisecondsInOneDay} = require("../src/validateDependencies.js")
const Octokit = require('octokit').Octokit

jest.mock('octokit')

process.env.GITHUB_REPOSITORY = 'adatree/validate-dependabot-vulnerabilities-action'

test('Build succeeds in case of no vulnerabilities identified', async () => {
    const dependabotNoOpenAlerts = []
    Octokit.mockImplementation(() => ({
        request: () => dependabotNoOpenAlerts
    }))
    expect(validateDependencies).not.toThrow()
})

test('Build passes for medium vulnerabilities newer than 1 month', async() => {
    const dateOffset = millisecondsInOneDay * 29
    const dependabotAlerts = [
        {
            "number": 1,
            "state": "open",
            "created_at": new Date().setTime(new Date() - dateOffset).toString(),
            "vulnerabilities": {
                "severity": "medium"
            }
        }
    ]
    Octokit.mockImplementation(() => ({
        request: () => dependabotAlerts
    }))
    expect(validateDependencies).not.toThrow()
})

test('Build fails for medium vulnerabilities older than 1 month', async() => {
    const dateOffset = millisecondsInOneDay * 31
    const dependabotAlerts = [
        {
            "number": 1,
            "state": "open",
            "created_at": new Date().setTime(new Date() - dateOffset).toString(),
            "vulnerabilities": {
                "severity": "medium"
            }
        }
    ]
    Octokit.mockImplementation(() => ({
        request: () => dependabotAlerts
    }))
    await expect(validateDependencies).rejects.toThrow()
})

test('Build passes for medium vulnerabilities newer than one month', async () => {
    const dateOffset = millisecondsInOneDay * 15
    const dependabotAlerts = [
        {
            "number": 1,
            "state": "open",
            "created_at": new Date().setTime(new Date() - dateOffset).toString(),
            "vulnerabilities": {
                "severity": "medium"
            }
        }
    ]
    Octokit.mockImplementation(() => ({
        request: () => dependabotAlerts
    }))
    expect(validateDependencies).not.toThrow()
})

test('Build fails for high vulnerabilities older than 14 days', async() => {
    const dateOffset = millisecondsInOneDay * 15
    const dependabotAlerts = [
        {
            "number": 1,
            "state": "open",
            "created_at": new Date().setTime(new Date() - dateOffset).toString(),
            "vulnerabilities": {
                "severity": "high"
            }
        }
    ]
    Octokit.mockImplementation(() => ({
        request: () => dependabotAlerts
    }))
    await expect(validateDependencies).rejects.toThrow()
})

test('Build passes for high vulnerabilities newer than 14 days', async () => {
    const dateOffset = millisecondsInOneDay * 13
    const dependabotAlerts = [
        {
            "number": 1,
            "state": "open",
            "created_at": new Date().setTime(new Date() - dateOffset).toString(),
            "vulnerabilities": {
                "severity": "high"
            }
        }
    ]
    Octokit.mockImplementation(() => ({
        request: () => dependabotAlerts
    }))
    expect(validateDependencies).not.toThrow()
})

test('Build fails for critical vulnerabilities older than 2 days', async () => {
    const dateOffset = millisecondsInOneDay * 3
    const dependabotAlerts = [
        {
            "number": 1,
            "state": "open",
            "created_at": new Date().setTime(new Date() - dateOffset).toString(),
            "vulnerabilities": {
                "severity": "critical"
            }
        }
    ]
    Octokit.mockImplementation(() => ({
        request: () => dependabotAlerts
    }))
    await expect(validateDependencies).rejects.toThrow()
})

test('Build passes for critical vulnerabilities newer than 2 days', async () => {
    const dependabotAlerts = [
        {
            "number": 1,
            "state": "open",
            "created_at": new Date().setTime(new Date() - millisecondsInOneDay).toString(),
            "vulnerabilities": {
                "severity": "critical"
            }
        }
    ]
    Octokit.mockImplementation(() => ({
        request: () => dependabotAlerts
    }))
    expect(validateDependencies).not.toThrow()
})


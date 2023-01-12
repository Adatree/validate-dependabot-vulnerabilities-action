const validateDependencies = require("./validateDependencies.js")
const Octokit = require('octokit').Octokit

jest.mock('octokit')

test('Build succeeds in case of no vulnerabilities identified', async () => {
    const dependabotNoOpenAlerts = [
        {
            "number": 2,
            "state": "dismissed",
            "created_at": "2022-06-14T15:21:52Z",
            "vulnerabilities": {
                "severity": "medium"
            }
        },
        {
            "number": 2,
            "state": "dismissed",
            "created_at": "2022-06-14T15:21:52Z",
            "vulnerabilities": {
                "severity": "medium"
            }
        }
    ]
    Octokit.mockImplementation(() => ({
        request: () => dependabotNoOpenAlerts
    }))
    expect(validateDependencies).not.toThrowError()
})

test('Build fails for medium vulnerabilities older than 1 month', async() => {
    const dateOffset = 24*60*60*1000 * 30
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
    expect(validateDependencies).toThrowError()
})

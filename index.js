const validateDependencies = require('validateDependencies.js')

async function run() {
  await validateDependencies()
}

await run();
